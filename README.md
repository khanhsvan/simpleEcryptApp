This is a Python application using a graphical user interface (GUI) to encrypt and decrypt files using various encryption algorithms such as Caesar, Playfair, RSA, and AES.
Requirements
Python 3.x
Necessary libraries installed, can be installed by running:
```bash
pip install -r requirements.txt
```
pip install -r requirements.txt
Usage Guide
Open the application by running the main.py file.
Choose the encryption method from the list of available methods.
Select the source file you want to encrypt by clicking the "Select Source file" button and choosing the corresponding file in the opened dialog box.
Choose the location and name of the destination file where you want to save the encrypted file by clicking the "Select Destination File" button and selecting the location and name in the opened dialog box.
Press the "Encrypt" button to encrypt the file.
To decrypt a file, select the decryption method from the list of available methods.
Choose the encrypted file you want to decrypt by clicking the "Select Source file" button and choosing the corresponding file in the opened dialog box.
Choose the location and name of the destination file where you want to save the decrypted file by clicking the "Select Destination File" button and selecting the location and name in the opened dialog box.
Press the "Decrypt" button to decrypt the file.
Note
When using AES, you will be prompted to enter a key of length 16, 24, or 32 characters. Make sure you enter a valid key.
When using RSA, you will need to generate an RSA key pair beforehand. Remember to securely store the private key.
