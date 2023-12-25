from flask import Flask, render_template, request
from main import bits_to_image, image_to_bits
import base64
import zlib
from PIL import Image
from cryptography.fernet import Fernet
import os

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/upload", methods=['POST'])
def upload():
    if 'file' not in request.files:
        return render_template('index.html', error='No file')

    file = request.files['file']

    if file.filename == '':
        return render_template('index.html', error='No selected file')

    image_path = 'static/images/' + file.filename
    file.save(image_path)

    return render_template('index.html', image_path=image_path)

@app.route("/encrypt", methods=['POST'])
def encrypt():
    image_path = request.form.get('image_path', '')
    print(image_path)
    encrypted_data, width, height, fernet = image_to_bits(image_path)
    output_path = 'static/encrypted_image.jpg'
    return render_template('index.html', value="encrypted")


@app.route("/decrypt", methods=['POST'])
def decrypt():
    image_path = request.form.get('image_path', '')
    print("path is: " + image_path)
    encrypted_data, width, height, fernet = image_to_bits(image_path)
    output_path = 'static/decrypted_image.jpg'
    bits_to_image(encrypted_data, width, height, output_path, fernet)
    return render_template('index.html', image_path=output_path)

if __name__ == '__main__':
    app.run(debug=True)
