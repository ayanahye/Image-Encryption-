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


def encrypt_image(image_path, password):
    img = Image.open(image_path)

    img_bytes = BytesIO()
    img.save(img_bytes, format="PNG")
    img_data = img_bytes.getvalue()

    compressed_data = zlib.compress(img_data)

    encoded_data = base64.b64encode(compressed_data).decode('utf-8')

    encrypted_data = encrypt_data(encoded_data, password)

    return encrypted_data

def decrypt_image(encrypted_data, password):
    decoded_data = decrypt_data(encrypted_data, password)

    compressed_data = base64.b64decode(decoded_data)

    img_data = zlib.decompress(compressed_data)

    img = Image.open(BytesIO(img_data))

    return img


def encrypt_data(image, password):
    img_bytes = image.tobytes()

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    encrypted_data = fernet.encrypt(img_bytes)

    #print(encrypted_data)
    return salt + encrypted_data

def decrypt_data(encrypted_data, password, image_width, image_height):
    # Modify this line in decrypt_data function

    #print(encrypted_data)
    encrypted_data_bytes = encrypted_data

    salt = encrypted_data_bytes[:16]
    encrypted_img_bytes = encrypted_data_bytes[16:]

    key = derive_key(password, salt)

    fernet = Fernet(key)

    decrypted_img_bytes = fernet.decrypt(encrypted_img_bytes)

    print("Original Image Size:", (image_width, image_height))
    print("Decrypted Image Size:", Image.frombytes("RGB", (image_width, image_height), decrypted_img_bytes).size)

    Image.frombytes("RGB", (image_width, image_height), decrypted_img_bytes).save("decrypted.png")

    img = Image.frombytes("RGB", (image_width, image_height), decrypted_img_bytes)
    img.save("original.png")


    return img


