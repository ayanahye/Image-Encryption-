import base64
import zlib
from PIL import Image
from cryptography.fernet import Fernet

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
    print("Encrypted Data: ", encrypted_data)


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
    key_U = input("Enter any key to begin: ")
    encrypted_data, width, height, fernet = image_to_bits(image_path)
    #print(text_data)

    output_path = 'reconstruct_image.jpg'

    bits_to_image(encrypted_data, width, height, output_path, fernet)

if __name__ == "__main__":
    main()