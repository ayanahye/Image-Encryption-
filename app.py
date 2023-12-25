from flask import Flask, render_template, request, send_file
from PIL import Image
import os
import base64
import zlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from io import BytesIO

# not good idea to make global variables, will fix
image_width = None
image_height = None

app = Flask(__name__)


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

def encrypt_image(img, password):
    # converts pixel values of image to binary strings
    # for each color channel
    # .getdata will return the contents of the image as a sequence object containing pixel values
    # convert to a list to get oridinary sequence for printing otherwise it is an PIL data type
    
    global image_width, image_height

    image_width = img.width
    image_height = img.height

    print(image_height)
    print(image_width)

    pixels = list(img.getdata())

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
    return salt + encrypted_data, fernet

def decrypt_image(encrypted_data, image_width, image_height, password):
    # Use image_width and image_height parameters

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

    print(image_height)
    print(image_width)
 
    red_channel = decompressed_data[:image_width * image_height * 8]
    green_channel = decompressed_data[image_width * image_height * 8:2 * image_width * image_height * 8]
    blue_channel = decompressed_data[2 * image_width * image_height * 8:]

    # convert binary values of each channel to integers
    red_pixels = [int(red_channel[i:i + 8], 2) for i in range(0, len(red_channel), 8)]
    green_pixels = [int(green_channel[i:i + 8], 2) for i in range(0, len(green_channel), 8)]
    blue_pixels = [int(blue_channel[i:i + 8], 2) for i in range(0, len(blue_channel), 8)]

    # recontruct the pixels and save to a new colored image
    reconstructed_pixels = list(zip(red_pixels, green_pixels, blue_pixels))

    new_img = Image.new("RGB", (image_width, image_height))
    new_img.putdata(reconstructed_pixels)
    new_img.save("help.jpg")
    return new_img

@app.route('/decrypt', methods=['GET'])
def decrypt_page():
    return render_template('decrypt.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return "No file provided"

    file = request.files['file']

    if file.filename == '':
        return "No file selected"

    password = request.form['password']

    encrypted_data = file.read()

    img = decrypt_image(encrypted_data, image_width, image_height, password)

    img_io = BytesIO()
    img.save(img_io, 'JPEG')
    img_io.seek(0)
    img_data = base64.b64encode(img_io.read()).decode('utf-8')

    return render_template('decrypt.html', decrypted_image=img_data)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file provided"

    file = request.files['file']

    if file.filename == '':
        return "No file selected"

    password = request.form['password']

    img = Image.open(file)

    encrypted_data, fernet = encrypt_image(img, password)

    encrypted_path = 'static/encrypted_data.bin'
    with open(encrypted_path, 'wb') as file:
        file.write(encrypted_data)
    return render_template('upload_success.html', encrypted_path=encrypted_path)

@app.route('/download/<password>')
def download(password):
    encrypted_path = 'static/encrypted_data.bin'

    with open(encrypted_path, 'rb') as file:
        encrypted_data = file.read()

    img = decrypt_image(encrypted_data, image_width, image_height, password)

    decrypted_path = 'static/decrypted_image.jpg'
    img.save(decrypted_path)

    return send_file(decrypted_path, as_attachment=True, download_name='decrypted_image.jpg')

if __name__ == '__main__':
    app.run(debug=True)
