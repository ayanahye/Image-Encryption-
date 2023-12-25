import base64
import zlib
from PIL import Image
from cryptography.fernet import Fernet
import numpy as np

def pixelize_image(image_path, pixel_size):
    img = Image.open(image_path)
    small_img = img.resize(
        (img.width // pixel_size, img.height // pixel_size),
        resample=Image.Resampling.NEAREST
    )
    pixelized_img = small_img.resize(img.size, Image.Resampling.NEAREST)
    return pixelized_img

def image_to_bits(image_path):
    valid_extensions = {'jpg', 'jpeg', 'png'}
    file_extension = image_path.lower().split('.')[-1]
    print(file_extension)

    if file_extension not in valid_extensions:
        raise ValueError("unsupported file type. Supported types are: jpg, jpeg, png")


    with open(image_path, "rb") as imageFile:
        img = Image.open(imageFile)
        pixels = list(img.getdata())

        red_channel = ''.join(format(pixel[0], '08b') for pixel in pixels)
        green_channel = ''.join(format(pixel[1], '08b') for pixel in pixels)
        blue_channel = ''.join(format(pixel[2], '08b') for pixel in pixels)

    compressed_data = zlib.compress((red_channel + green_channel + blue_channel).encode('utf-8'))
    key_F = Fernet.generate_key()
    fernet = Fernet(key_F)

    encrypted_data = fernet.encrypt(compressed_data)

    #print("Original Data: ", compressed_data)
    #print("Encrypted Data: ", encrypted_data)


    return encrypted_data, img.width, img.height, fernet

def bits_to_image(encrypted_data, width, height, output_path, fernet):
    decrypted_data = fernet.decrypt(encrypted_data)
    #print("Decrypted Data: ", decrypted_data)

    decompressed_data = zlib.decompress(decrypted_data).decode('utf-8')

    red_channel = decompressed_data[:width * height * 8]
    green_channel = decompressed_data[width * height * 8:2 * width * height * 8]
    blue_channel = decompressed_data[2 * width * height * 8:]

    red_pixels = [int(red_channel[i:i+8], 2) for i in range(0, len(red_channel), 8)]
    green_pixels = [int(green_channel[i:i+8], 2) for i in range(0, len(green_channel), 8)]
    blue_pixels = [int(blue_channel[i:i+8], 2) for i in range(0, len(blue_channel), 8)]

    reconstructed_pixels = list(zip(red_pixels, green_pixels, blue_pixels))

    new_img = Image.new("RGB", (width, height))
    new_img.putdata(reconstructed_pixels)

    new_img.save(output_path)

def main():
    image_path = 'cat.jpg'
    pixel_size = 70  
    output_path = 'pixelized_image.jpg'

    pixelized_img = pixelize_image(image_path, pixel_size)
    pixelized_img.save(output_path)

    encrypted_data, width, height, fernet = image_to_bits(image_path)

    with open('encrypted_data.bin', 'wb') as file:
        file.write(encrypted_data)

    bits_to_image(encrypted_data, width, height, 'reconstructed_image.jpg', fernet)

if __name__ == "__main__":
    main()