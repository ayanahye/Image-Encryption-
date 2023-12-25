from flask import Flask, render_template, request, send_file, url_for
from PIL import Image
import os
import base64
import zlib
from io import BytesIO
from image_encryptor import encrypt_image, decrypt_image, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


# not good idea to make global variables, will fix
image_width = None
image_height = None

app = Flask(__name__)

@app.route('/decrypt', methods=['GET'])
def decrypt_page():
    return render_template('decrypt.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'encrypted_image' not in request.files:
        return "No file provided"

    file = request.files['encrypted_image']

    if file.filename == '':
        return "No file selected"

    password = request.form['key']

    img = decrypt_data(file.read(), password, image_width, image_height)

    img_bytes = BytesIO()
    img.save(img_bytes, format="PNG")
    img_data = base64.b64encode(img_bytes.getvalue()).decode('utf-8')

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

    global image_width, image_height
    image_width = img.width
    image_height = img.height

    encrypted_data = encrypt_data(img, password)

    return send_file(BytesIO(encrypted_data.encode('utf-8')), as_attachment=True, download_name='encrypted_image.png')


@app.route('/download/<password>')
def download(password):

    return send_file(decrypted_path, as_attachment=True, download_name='decrypted_image.jpg')

if __name__ == '__main__':
    app.run(debug=True)
