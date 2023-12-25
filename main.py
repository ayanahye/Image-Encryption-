# encoding/decoding functions for base64
import base64
# file handling
import os
# compression and decompression
import zlib
# image processing library
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
# for numerical operations
import numpy as np

# takes a pass and a salt and uses PBKDF2 with SHA256 as the
# hash function to derive a key, the key is encoded in base64 and returned
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

def pixelize_image(image_path, block_size):
    img = Image.open(image_path)
    width, height = img.size
    # resize image taking params size and resample
    # resampling.nearest will pick one nearest pixel from the input image and ignore all other pixels
    # so that the image can be pixelized efficiently

    # block_size passed so user can specify how many pixelated they want the image
    pixelized_img = img.resize(
        (width // block_size, height // block_size),
        resample=Image.Resampling.NEAREST
    )
    pixelized_img = pixelized_img.resize(img.size, resample=Image.Resampling.NEAREST)
    
    return pixelized_img

# takes the pixelized image
def image_to_bits(pixelized_img, password):
    # converts pixel values of image to binary strings
    # for each color channel
    # .getdata will return the contents of the image as a sequence object containing pixel values
    # convert to a list to get oridinary sequence for printing otherwise it is an PIL data type
    pixels = list(pixelized_img.getdata())

    # rgb for each pixel in the pixels array and concatenate
    red_channel = ''.join(format(pixel[0], '08b') for pixel in pixels)
    green_channel = ''.join(format(pixel[1], '08b') for pixel in pixels)
    blue_channel = ''.join(format(pixel[2], '08b') for pixel in pixels)

    # compress the binary strings after concatenating

    compressed_data = zlib.compress((red_channel + green_channel + blue_channel).encode('utf-8'))
    
    # generate a random salt
    salt = os.urandom(16)

    # use the derive key function with the password from the user and the salt
    # Fernet symmetric encryption
    key = derive_key(password, salt)

    # Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key
    fernet = Fernet(key)

    # A secure message that cannot be read or altered without the key. It is URL-safe base64-encoded. This is referred to as a “Fernet token”.
    encrypted_data = fernet.encrypt(compressed_data)

    # add salt to data for extra protection
    return salt + encrypted_data, pixelized_img.width, pixelized_img.height, fernet

# takes the encrypted data from the pixelized image with the salt
def bits_to_image(encrypted_data, width, height, output_path, password):
    # remove the salt
    salt = encrypted_data[:16]
    # get the actual encrypted image data
    encrypted_data = encrypted_data[16:]

    # derive the key
    key = derive_key(password, salt)

    fernet = Fernet(key)

    # decrypt using the key from Fernet
    decrypted_data = fernet.decrypt(encrypted_data)

    # decompress and convert back to separate color channels
    decompressed_data = zlib.decompress(decrypted_data).decode('utf-8')
 
    red_channel = decompressed_data[:width * height * 8]
    green_channel = decompressed_data[width * height * 8:2 * width * height * 8]
    blue_channel = decompressed_data[2 * width * height * 8:]

    # convert binary values of each channel to integers
    red_pixels = [int(red_channel[i:i + 8], 2) for i in range(0, len(red_channel), 8)]
    green_pixels = [int(green_channel[i:i + 8], 2) for i in range(0, len(green_channel), 8)]
    blue_pixels = [int(blue_channel[i:i + 8], 2) for i in range(0, len(blue_channel), 8)]

    # recontruct the pixels and save to a new colored image
    reconstructed_pixels = list(zip(red_pixels, green_pixels, blue_pixels))

    new_img = Image.new("RGB", (width, height))
    new_img.putdata(reconstructed_pixels)

    new_img.save(output_path)

def main():
    image_path = 'cat.jpg'
    block_size = 5
    output_path = 'reconstructed_image.jpg'
    password = input("Please input a key to decrypt the image?: ")

    pixelized_img = pixelize_image(image_path, block_size)

    encrypted_data, width, height, fernet = image_to_bits(pixelized_img, password)

    with open('encrypted_data.bin', 'wb') as file:
        file.write(encrypted_data)

    bits_to_image(encrypted_data, width, height, output_path, password)

if __name__ == "__main__":
    main()
