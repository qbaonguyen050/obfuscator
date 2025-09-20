# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Install git and git-lfs for repository tooling
RUN apt-get update && apt-get install -y git git-lfs && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /workspace

# Copy the requirements file from the build context (project root)
COPY requirements.txt .

# Copy the rest of the application code from the build context
COPY . .

# Expose the port the app runs on
EXPOSE 6080