from flask import Flask, render_template, request, send_file, jsonify
import cv2
import os
import base64
import numpy as np

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Generate AES key from password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt message using AES
def encrypt_message(message: str, password: str) -> bytes:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return salt + iv + ciphertext

# Decrypt message using AES
def decrypt_message(encrypted_message: bytes, password: str) -> str:
    salt = encrypted_message[:16]
    iv = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_bytes) + unpadder.finalize()

    return unpadded_message.decode()

# Hide encrypted message in image
def hide_message(image_path: str, message: str, password: str, output_path: str):
    encrypted_message = encrypt_message(message, password)
    encoded_message = base64.b64encode(encrypted_message).decode() + "@@END@@"

    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    
    if img is None:
        raise ValueError("Error: Unable to load image.")

    index = 0
    for char in encoded_message:
        if index >= img.shape[0] * img.shape[1]:
            raise ValueError("Error: Message too large for image")
        img[index // img.shape[1], index % img.shape[1], 0] = ord(char)
        index += 1

    cv2.imwrite(output_path, img)

# Extract encrypted message from image
def extract_message(image_path: str, password: str):
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)

    if img is None:
        raise ValueError("Error: Unable to load image.")

    chars = []
    index = 0

    while index < img.shape[0] * img.shape[1]:
        char = chr(img[index // img.shape[1], index % img.shape[1], 0])
        chars.append(char)
        if ''.join(chars[-7:]) == "@@END@@":
            break
        index += 1

    if index >= img.shape[0] * img.shape[1]:
        raise ValueError("Error: No hidden message found or message incomplete")

    encoded_message = ''.join(chars[:-7])
    encrypted_message = base64.b64decode(encoded_message)
    return decrypt_message(encrypted_message, password)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    image = request.files['image']
    message = request.form['message']
    password = request.form['password']
    image_path = 'temp_input.png'
    output_path = 'static/encrypted_image.png'
    image.save(image_path)
    try:
        hide_message(image_path, message, password, output_path)
        return send_file(output_path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    image = request.files['image']
    if not image:
        return jsonify({'error': 'No image uploaded'}), 400

    image_path = 'temp_decrypt.png'
    image.save(image_path)  

    password = request.form['password']

    try:
        decrypted_message = extract_message(image_path, password)
        print(f"🔍 Decrypted Message: {decrypted_message}")  # Debugging line
        return jsonify({'message': decrypted_message})
    except Exception as e:
        print(f"❌ Decryption Error: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
