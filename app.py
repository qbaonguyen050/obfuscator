import os
import base64
from flask import Flask, render_template, request, jsonify
from quantcrypt.kem import MLKEM_768
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

SALT_SIZE = 16
PBKDF_ITERATIONS = 600000
AES_NONCE_SIZE = 12

def generate_master_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        plaintext = data['text'].encode('utf-8')
        password = data['password']

        # CORRECT FUNCTION: keygen()
        private_key, public_key = MLKEM_768.keygen()

        # CORRECT FUNCTION: encaps()
        ciphertext_kem, shared_secret = MLKEM_768.encaps(public_key)

        salt = os.urandom(SALT_SIZE)
        master_key = generate_master_key(password, salt)
        master_key_aesgcm = AESGCM(master_key)
        master_key_nonce = os.urandom(AES_NONCE_SIZE)
        encrypted_private_key = master_key_aesgcm.encrypt(
            master_key_nonce,
            private_key, # The private key object itself is bytes-like
            None
        )
        data_aesgcm = AESGCM(shared_secret)
        data_nonce = os.urandom(AES_NONCE_SIZE)
        ciphertext_aes = data_aesgcm.encrypt(data_nonce, plaintext, None)
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
        return jsonify({'success': True, 'result': base64.b64encode(payload).decode('utf-8')})
    except Exception as e:
        return jsonify({'success': False, 'error': f"An unexpected encryption error occurred: {str(e)}"})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        password = data['password']
        payload = base64.b64decode(data['text'])
        cursor = 0
        salt = payload[cursor:cursor + SALT_SIZE]; cursor += SALT_SIZE
        master_key_nonce = payload[cursor:cursor + AES_NONCE_SIZE]; cursor += AES_NONCE_SIZE
        encrypted_pk_len = int.from_bytes(payload[cursor:cursor+4], 'big'); cursor += 4
        encrypted_private_key = payload[cursor:cursor+encrypted_pk_len]; cursor += encrypted_pk_len
        ciphertext_kem = payload[cursor:cursor + MLKEM_768.CIPHERTEXT_LENGTH]; cursor += MLKEM_768.CIPHERTEXT_LENGTH
        data_nonce = payload[cursor:cursor + AES_NONCE_SIZE]; cursor += AES_NONCE_SIZE
        ciphertext_aes = payload[cursor:]
        master_key = generate_master_key(password, salt)
        master_key_aesgcm = AESGCM(master_key)
        
        # The private key is decrypted directly
        private_key = master_key_aesgcm.decrypt(
            master_key_nonce,
            encrypted_private_key,
            None
        )

        # CORRECT FUNCTION: decaps()
        shared_secret = MLKEM_768.decaps(private_key, ciphertext_kem)

        data_aesgcm = AESGCM(shared_secret)
        plaintext_bytes = data_aesgcm.decrypt(data_nonce, ciphertext_aes, None)
        return jsonify({'success': True, 'result': plaintext_bytes.decode('utf-8')})
    except (InvalidTag, ValueError, IndexError):
        return jsonify({'success': False, 'error': "Decryption failed. Please check your password and the encrypted text."})
    except Exception as e:
        return jsonify({'success': False, 'error': f"An unexpected decryption error occurred: {str(e)}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6080, debug=True)
