import os
import base64
from flask import Flask, render_template, request, jsonify
from quantcrypt.kem import MLKEM768
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- Flask App Setup ---
app = Flask(__name__)

# --- Cryptographic Constants ---
SALT_SIZE = 16
PBKDF_ITERATIONS = 600000  # NIST recommendation for PBKDF2
AES_NONCE_SIZE = 12 # 96 bits is recommended for GCM

def generate_master_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte master key from a password using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

@app.route('/')
def index():
    """Renders the main HTML page."""
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Handles the encryption request from the web page."""
    try:
        data = request.json
        plaintext = data['text'].encode('utf-8')
        password = data['password']

        # 1. Generate Post-Quantum key pair
        private_key, public_key = MLKEM768.generate_keypair()

        # 2. Encapsulate a shared secret for AES data encryption
        ciphertext_kem, shared_secret = MLKEM768.encapsulate_shared_secret(public_key)

        # 3. Derive master key from password to protect the PQC private key
        salt = os.urandom(SALT_SIZE)
        master_key = generate_master_key(password, salt)
        
        # 4. Encrypt the ML-KEM private key with the master key
        master_key_aesgcm = AESGCM(master_key)
        master_key_nonce = os.urandom(AES_NONCE_SIZE)
        encrypted_private_key = master_key_aesgcm.encrypt(
            master_key_nonce,
            private_key.private_key_bytes,
            None
        )

        # 5. Encrypt the actual plaintext data with the shared secret
        data_aesgcm = AESGCM(shared_secret)
        data_nonce = os.urandom(AES_NONCE_SIZE)
        ciphertext_aes = data_aesgcm.encrypt(data_nonce, plaintext, None)

        # 6. Assemble the final payload for storage/transmission
        # Format: salt | master_key_nonce | len(enc_pk) | enc_pk | kem_ct | data_nonce | aes_ct
        encrypted_private_key_len = len(encrypted_private_key).to_bytes(4, 'big')
        
        payload = (
            salt +
            master_key_nonce +
            encrypted_private_key_len +
            encrypted_private_key +
            ciphertext_kem +
            data_nonce +
            ciphertext_aes
        )

        # Return as Base64 for easy copy-pasting
        return jsonify({'success': True, 'result': base64.b64encode(payload).decode('utf-8')})

    except Exception as e:
        return jsonify({'success': False, 'error': f"An unexpected encryption error occurred: {str(e)}"})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Handles the decryption request from the web page."""
    try:
        data = request.json
        password = data['password']
        
        # 1. Decode the Base64 payload
        payload = base64.b64decode(data['text'])

        # 2. Parse the payload into its components by slicing
        cursor = 0
        salt = payload[cursor:cursor + SALT_SIZE]; cursor += SALT_SIZE
        master_key_nonce = payload[cursor:cursor + AES_NONCE_SIZE]; cursor += AES_NONCE_SIZE
        
        encrypted_pk_len = int.from_bytes(payload[cursor:cursor+4], 'big'); cursor += 4
        encrypted_private_key = payload[cursor:cursor+encrypted_pk_len]; cursor += encrypted_pk_len
        
        ciphertext_kem = payload[cursor:cursor + MLKEM768.CIPHERTEXT_LENGTH]; cursor += MLKEM768.CIPHERTEXT_LENGTH
        data_nonce = payload[cursor:cursor + AES_NONCE_SIZE]; cursor += AES_NONCE_SIZE
        ciphertext_aes = payload[cursor:]

        # 3. Re-derive the master key from the password and salt
        master_key = generate_master_key(password, salt)

        # 4. Decrypt the ML-KEM private key
        master_key_aesgcm = AESGCM(master_key)
        private_key_bytes = master_key_aesgcm.decrypt(
            master_key_nonce,
            encrypted_private_key,
            None
        )
        private_key = MLKEM768.private_key_from_bytes(private_key_bytes)

        # 5. Decapsulate to retrieve the shared secret
        shared_secret = MLKEM768.decapsulate_shared_secret(private_key, ciphertext_kem)

        # 6. Decrypt the actual data
        data_aesgcm = AESGCM(shared_secret)
        plaintext_bytes = data_aesgcm.decrypt(data_nonce, ciphertext_aes, None)

        return jsonify({'success': True, 'result': plaintext_bytes.decode('utf-8')})

    except (InvalidTag, ValueError, IndexError):
        # InvalidTag means wrong password/tampered data. Others for parsing errors.
        return jsonify({'success': False, 'error': "Decryption failed. Please check your password and the encrypted text."})
    except Exception as e:
        return jsonify({'success': False, 'error': f"An unexpected decryption error occurred: {str(e)}"})

if __name__ == '__main__':
    # Flask will run on 0.0.0.0:6080 inside the container.
    # GitHub Codespaces will forward this port securely to a public URL.
    app.run(host='0.0.0.0', port=6080, debug=True)