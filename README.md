## About Image Encryption 

This is a encryption project that allows the user to input an image (.jpg, .png, .jpeg) file and a password. The password is used alongside a randomly generated salt to create a key using the SHA256 hash function.

Once the key is created it is used to encrypt the bytes of the image using Fernet symmetric encryption. The dimensions of the image are also encrypted and accessed in the decryption function.

If the user inputs the wrong password they will get an error. If the key is correct then they will be able to decrypt the image. 

## Website

Link to Website: [Click Here](https://ayanahye3.pythonanywhere.com/).

Please email me at once.ayana@gmail.com if there are any bugs or errors and I will resolve them. Thank you.


