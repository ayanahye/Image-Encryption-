# image_encryptor.py

from PIL import Image
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from io import BytesIO
from cryptography.fernet import Fernet
import binascii

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10,
        backend=default_backend()
    )
    # encode password first then derive the key
    # convert key to base 64
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(image, password, width, height):
    img_bytes = image.tobytes()

    img_data_with_dimensions = width.to_bytes(4, 'big') + height.to_bytes(4, 'big') + img_bytes

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    encrypted_data = fernet.encrypt(img_data_with_dimensions)

    #print(encrypted_data)
    return salt + encrypted_data

def decrypt_data(encrypted_data, password):

    #print(encrypted_data)
    encrypted_data_bytes = encrypted_data

    salt = encrypted_data_bytes[:16]
    encrypted_img_bytes_with_dimensions = encrypted_data_bytes[16:]

    key = derive_key(password, salt)

    fernet = Fernet(key)

    img_data_with_dimensions = fernet.decrypt(encrypted_img_bytes_with_dimensions)

    img_width = int.from_bytes(img_data_with_dimensions[:4], 'big')
    img_height = int.from_bytes(img_data_with_dimensions[4:8], 'big')

    img_bytes = img_data_with_dimensions[8:]

    print("Original Image Size:", (img_width, img_height))

    img = Image.frombytes("RGB", (img_width, img_height), img_bytes)
    img.save("decrypted.png")


    return img


