from PIL import Image
from image_encryptor import encrypt_data, decrypt_data

image_path = 'cat.jpg'
password = 'hi'

img = Image.open(image_path)
img.show()

encrypted_data = encrypt_data(img, password)

decrypted_img = decrypt_data(encrypted_data, password, img.width, img.height)
decrypted_img.show()
