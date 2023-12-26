from flask import Flask, render_template, request, send_file, url_for
from PIL import Image
import os
import base64
import zlib
from io import BytesIO
from image_encryptor import encrypt_data, decrypt_data
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

app = Flask(__name__)

class image_processor:
    def __init__(self):
        self.image_width = None
        self.image_height = None

    def get_height(self):
        return self.image_height
    
    def get_width(self):
        return self.image_width

    def set_height(self, value):
        self.image_height = value

    def set_width(self, value):
        self.image_width = value

image_processor = image_processor()

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file provided"

    file = request.files['file']

    if file.filename == '':
        return "No file selected"

    password = request.form['password']

    img = Image.open(file)

    image_processor.set_width(img.width)
    image_processor.set_height(img.height)

    encrypted_data = encrypt_data(img, password, img.width, img.height)
    #print(encrypted_data)

    file_name = f'encrypted_image.png'
    encrypted_image_path = 'static/images/encrypted_image.png'

    #return send_file(BytesIO(encrypted_data), as_attachment=True, download_name=file_name)

    original_image_data = BytesIO()
    img.save(original_image_data, format='PNG')
    original_image_data.seek(0)

    original_image_base64 = base64.b64encode(original_image_data.read()).decode('utf-8')
    #encrypted_image_base64 = base64.b64encode(BytesIO(encrypted_data).read()).decode('utf-8')
    with open(encrypted_image_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    return render_template('index.html', original_image_base64=original_image_base64, encrypted_image_path=encrypted_image_path)

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

    img = decrypt_data(file.read(), password)

    img_bytes = BytesIO()
    img.save(img_bytes, format="PNG")
    img_data = base64.b64encode(img_bytes.getvalue()).decode('utf-8')

    return render_template('decrypt.html', decrypted_image=img_data)



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/download_encrypted/<filename>')
def download_encrypted(filename):
    encrypted_path = os.path.join('static/images', filename)
    return send_file(encrypted_path, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True)
