#!/usr/bin/env python3

import os
import numpy as np
import hashlib
from Crypto.Cipher import AES
from stegano.lsb import hide, reveal

try:
    from qiskit import QuantumCircuit, Aer, execute
except ModuleNotFoundError:
    print("Warning: Qiskit is not installed. Using a pseudo-random key generator instead.")
    QISKIT_AVAILABLE = False
else:
    QISKIT_AVAILABLE = True

# Quantum Key Distribution (Simulated BB84 Protocol or Fallback)
def generate_qkd_key(length=16):
    if QISKIT_AVAILABLE:
        simulator = Aer.get_backend('qasm_simulator')
        qc = QuantumCircuit(length, length)
        qc.h(range(length))  # Apply Hadamard gate for superposition
        qc.measure(range(length), range(length))
        job = execute(qc, simulator, shots=1)
        result = job.result().get_counts()
        key_bin = list(result.keys())[0]  # Extract key
        key_bytes = bytes(int(key_bin[i:i+8], 2) for i in range(0, length, 8))
        return key_bytes[:16]  # Return 16-byte AES key
    else:
        return bytes(np.random.randint(0, 256, 16).tolist())  # Fallback to random key

# AES-256 Encryption
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    message_padded = message + (16 - len(message) % 16) * ' '
    encrypted_message = cipher.encrypt(message_padded.encode())
    return encrypted_message

# AES-256 Decryption
def decrypt_message(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message).decode().strip()
    return decrypted_message

# SHA-3 Hashing
def generate_hash(message):
    return hashlib.sha3_256(message).hexdigest()

# Embedding Data using LSB Steganography
def hide_data(image_path, encrypted_message, hash_value):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Error: The file '{image_path}' does not exist. Please provide a valid image.")
    
    combined_data = encrypted_message.hex() + ':' + hash_value
    secret_image = hide(image_path, combined_data)
    secret_image.save("stego_image.png")
    print("✅ Data successfully hidden in 'stego_image.png'.")

# Extracting Data
def extract_data(stego_image_path, key):
    if not os.path.exists(stego_image_path):
        raise FileNotFoundError(f"Error: The file '{stego_image_path}' does not exist. Cannot extract hidden data.")
    
    extracted_data = reveal(stego_image_path)
    encrypted_message_hex, original_hash = extracted_data.split(':')
    encrypted_message = bytes.fromhex(encrypted_message_hex)
    decrypted_message = decrypt_message(encrypted_message, key)

    if generate_hash(encrypted_message) == original_hash:
        print("✅ Integrity Verified!")
    else:
        print("❌ Warning: Data Tampering Detected!")

    return decrypted_message

# Main Execution
if __name__ == "__main__":
    # Ask user for the input image path
    input_image = input("Enter the path to the image file: ").strip()

    if not os.path.exists(input_image):
        print(f"❌ Error: '{input_image}' not found. Please provide a valid image path.")
    else:
        key = generate_qkd_key()
        message = input("Enter the secret message to hide: ")

        # Encryption & Hashing
        encrypted_message = encrypt_message(message, key)
        hash_value = generate_hash(encrypted_message)

        # Hide Data in Image
        hide_data(input_image, encrypted_message, hash_value)

        # Extraction on the receiver's side
        extract_confirmation = input("Do you want to extract the hidden message? (yes/no): ").strip().lower()
        if extract_confirmation == "yes":
            extracted_message = extract_data("stego_image.png", key)
            print("🔓 Decrypted Message:", extracted_message)
