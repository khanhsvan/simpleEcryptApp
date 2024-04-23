from tkinter import *
from tkinter import filedialog, simpledialog  # Import simpledialog for input dialog
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.Random import get_random_bytes
import random
import string

a = Tk()
a.title("ENCRYPTON-DECRYPTION")
a.geometry("500x600")

encryption_options = ["Caesar", "Playfair", "RSA", "AES"]


def mfileSourceopen():
    file = filedialog.askopenfile()
    if file:
        global fil1
        fil1 = file.name
        source_file_label.config(text=f"Selected Source File: {os.path.basename(fil1)}")


def mfileDestinationopen():
    file = filedialog.askopenfile()
    if file:
        global fil2
        fil2 = file.name
        destination_file_label.config(text=f"Selected Destination File: {os.path.basename(fil2)}")


def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("privatekey.pem", "wb") as f:
        f.write(private_key)
    with open("publickey.pem", "wb") as f:
        f.write(public_key)


def caesar_encrypt(plaintext, key):
    encrypted_text = ""
    for char in plaintext:
        if char.isalpha():  # Check if the character is an alphabet letter
            if char.islower():
                encrypted_text += chr((ord(char) - ord('a') + key) % 26 + ord('a'))
            else:
                encrypted_text += chr((ord(char) - ord('A') + key) % 26 + ord('A'))
        else:
            encrypted_text += char  # Keep non-alphabet characters unchanged
    return encrypted_text


def caesar_decrypt(ciphertext, key):
    decrypted_text = ""
    # Chuyển đổi ciphertext thành chuỗi Unicode trước khi lặp qua nó
    ciphertext = ciphertext.decode()
    for char in ciphertext:
        if char.isalpha():  # Check if the character is an alphabet letter
            if char.islower():
                decrypted_text += chr((ord(char) - ord('a') - key) % 26 + ord('a'))
            else:
                decrypted_text += chr((ord(char) - ord('A') - key) % 26 + ord('A'))
        else:
            decrypted_text += char  # Keep non-alphabet characters unchanged
    return decrypted_text


def AESEncrypt(plaintext, key):
    # Tạo đối tượng padder để đệm dữ liệu
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    # Đệm dữ liệu
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Tạo đối tượng cipher
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Mã hóa dữ liệu
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext, iv


def AESDecrypt(ciphertext, key, iv):
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data


def AESEncryptWithUserKey(plaintext, user_key):
    key = user_key.encode()  # Convert the user-provided key to bytes
    ciphertext, iv = AESEncrypt(plaintext, key)
    return ciphertext, iv


def AESDecryptWithUserKey(ciphertext, user_key, iv):
    if isinstance(user_key, str):
        key = user_key.encode()  # Convert the user-provided key to bytes if it's a string
    else:
        key = user_key  # Use the key as-is if it's already in bytes format
    plaintext = AESDecrypt(ciphertext, key, iv)
    return plaintext


def RSAEncrypt(message):
    with open("publickey.pem", "rb") as f:
        recipient_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_msg = cipher_rsa.encrypt(message.encode())
    return encrypted_msg

def prepare_playfair_key(key):
    # Loại bỏ khoảng trắng và chữ trùng lặp từ khóa
    key = key.replace(" ", "").upper()
    key_without_duplicates = "".join(dict.fromkeys(key))

    # Xây dựng bảng khóa
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Bỏ qua 'J'
    table = ""
    for char in key_without_duplicates:
        table += char
        alphabet = alphabet.replace(char, "")

    # Thêm phần còn lại của bảng chữ cái vào bảng khóa
    table += alphabet
    return table


def playfair_encrypt(plaintext, key):
    table = prepare_playfair_key(key)
    encrypted_text = ""
    
    # Modify plaintext to replace invalid characters
    plaintext = plaintext.replace("J", "I")  # Replace 'J' with 'I' since 'J' is usually combined with 'I'
    plaintext = plaintext.upper()  # Convert plaintext to uppercase
    
    for i in range(0, len(plaintext), 2):
        pair = plaintext[i:i+2]
        
        if len(pair) == 1:
            pair += 'X'  # Append 'X' to incomplete pairs
            
        row1, col1 = divmod(table.index(pair[0]), 5)
        row2, col2 = divmod(table.index(pair[1]), 5)
        
        if row1 == row2:
            encrypted_text += table[row1*5 + (col1+1) % 5]
            encrypted_text += table[row2*5 + (col2+1) % 5]
        elif col1 == col2:
            encrypted_text += table[((row1+1) % 5)*5 + col1]
            encrypted_text += table[((row2+1) % 5)*5 + col2]
        else:
            encrypted_text += table[row1*5 + col2]
            encrypted_text += table[row2*5 + col1]
    
    return encrypted_text



def playfair_decrypt(ciphertext, key):
    table = prepare_playfair_key(key)
    decrypted_text = ""
    
    # Modify ciphertext to replace invalid characters
    ciphertext = ciphertext.replace("J", "I")  # Replace 'J' with 'I' since 'J' is usually combined with 'I'
    ciphertext = ciphertext.upper()  # Convert ciphertext to uppercase
    
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i+2]
        
        if pair[0] not in table or pair[1] not in table:
            continue  # Skip characters not found in the key table
        
        row1, col1 = divmod(table.index(pair[0]), 5)
        row2, col2 = divmod(table.index(pair[1]), 5)
        
        if row1 == row2:
            decrypted_text += table[row1*5 + (col1-1) % 5]
            decrypted_text += table[row2*5 + (col2-1) % 5]
        elif col1 == col2:
            decrypted_text += table[((row1-1) % 5)*5 + col1]
            decrypted_text += table[((row2-1) % 5)*5 + col2]
        else:
            decrypted_text += table[row1*5 + col2]
            decrypted_text += table[row2*5 + col1]
    
    return decrypted_text


def Encrypt():
    global fil1, fil2
    with open(fil1, 'r') as f:
        plaintext = f.read()
    encryption_type = encryption_var.get()
    encrypted_msg = None  # Initialize encrypted_msg variable
    if encryption_type == "RSA":
        # Check if publickey.pem exists, if not, generate RSA key pair
        if not os.path.exists("publickey.pem"):
            generate_rsa_key_pair()
        # Encrypt using RSA
        encrypted_msg = RSAEncrypt(plaintext)
        print("Encrypted message with RSA:", encrypted_msg)  # Print encryption message
    elif encryption_type == "Caesar":
        # Get Caesar key from user
        caesar_key_str = simpledialog.askstring("Caesar Key", "Enter Caesar Key:")
        try:
            key = int(caesar_key_str)
        except ValueError:
            print("Invalid Caesar key. Please enter a valid integer key.")
            return
        encrypted_msg = caesar_encrypt(plaintext, key)
        print("Encrypted message with Caesar cipher:", encrypted_msg)  # Print encryption message
    elif encryption_type == "AES":
        user_key = simpledialog.askstring("AES Key", "Enter AES Key:")
        if not validate_aes_key(user_key):
            print("Invalid AES key length. Key must be 16, 24, or 32 characters long.")
            return
        ciphertext, iv = AESEncryptWithUserKey(plaintext, user_key)
        with open(fil2, 'wb') as fw:
            fw.write(ciphertext)
        with open(fil2 + ".iv", 'wb') as iv_file:
            iv_file.write(iv)
        print("Encrypted message with AES:", ciphertext)  # Print encryption message
        return
    elif encryption_type == "Playfair":
        key = simpledialog.askstring("Playfair Key", "Enter Playfair Key:")
        if key:
            encrypted_msg = playfair_encrypt(plaintext, key)
            print("Encrypted message with Playfair cipher:", encrypted_msg)
        else:
            print("No key provided.")
            return


    else:
        print("Invalid encryption method")

    if encrypted_msg is not None:  # Check if encrypted_msg has been assigned a value
        with open(fil2, 'wb') as fw:
            if encryption_type == "RSA":
                fw.write(encrypted_msg)
            elif encryption_type == "Caesar":
                fw.write(encrypted_msg.encode())
            elif encryption_type == "Playfair":
                fw.write(encrypted_msg.encode())
            else:
                fw.write(encrypted_msg)

    if encrypted_msg is not None:  # Print encrypted_msg only if it's not None
        print("Encrypted message:", encrypted_msg)


def Decrypt():
    global fil1, fil2
    with open(fil1, 'rb') as f:
        encrypted_msg = f.read()
    decryption_type = decryption_var.get()
    if decryption_type == "RSA":
        # Decrypt using RSA
        private_key_file = filedialog.askopenfile(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
        if private_key_file:
            with open(private_key_file.name, "rb") as f:
                private_key = RSA.import_key(f.read())
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted_msg = cipher_rsa.decrypt(encrypted_msg)
        else:
            print("No private key selected.")
            return
        print("Decrypted message with RSA:", decrypted_msg)  # Print decryption message
    elif decryption_type == "Caesar":
        # Get Caesar key from user
        caesar_key_str = simpledialog.askstring("Caesar Key", "Enter Caesar Key:")
        try:
            key = int(caesar_key_str)
        except ValueError:
            print("Invalid Caesar key. Please enter a valid integer key.")
            return
        decrypted_msg = caesar_decrypt(encrypted_msg, key)
        print("Decrypted message with Caesar cipher:", decrypted_msg)  # Print decryption message
    elif decryption_type == "AES":
        # Ask the user to select the IV file for AES decryption
        iv_file = filedialog.askopenfilename(title="Select AES IV File", filetypes=[("IV files", "*.iv")])
        if not iv_file:  # User did not select a file
            print("No IV file selected.")
            return
        with open(iv_file, 'rb') as ivf:
            iv = ivf.read()
        user_key = simpledialog.askstring("AES Key", "Enter AES Key:")
        decrypted_msg = AESDecryptWithUserKey(encrypted_msg, user_key, iv)  # Ensure correct order of arguments
        print("Decrypted message with AES:", decrypted_msg)  # Print decryption message
    elif decryption_type == "Playfair":
         key = simpledialog.askstring("Playfair Key", "Enter Playfair Key:")
         if key:
            decrypted_msg = playfair_decrypt(encrypted_msg.decode(), key)
            print("Decrypted message with Playfair cipher:", decrypted_msg)
         else:
            print("No key provided.")
            return

    else:
        # Decrypt using other algorithms
        # Add your decryption method calls here
        decrypted_msg = encrypted_msg  # Placeholder for other decryption methods
    with open(fil2, 'wb') as fw:
        if decryption_type == "RSA":
            fw.write(decrypted_msg)
        elif decryption_type == "Caesar":
            fw.write(decrypted_msg.encode())
        elif decryption_type == "AES":
            fw.write(decrypted_msg)
        else:
            fw.write(decrypted_msg.encode())

    print("Decrypted message:", decrypted_msg)


# Function to validate AES key length
def validate_aes_key(key):
    key_length = len(key)
    return key_length in [16, 24, 32]


# Variables to store selected encryption and decryption methods
encryption_var = StringVar(a)
encryption_var.set(encryption_options[0])

decryption_var = StringVar(a)
decryption_var.set(encryption_options[0])

# Encryption method selection
encryption_menu_label = Label(a, text="Encryption Method:")
encryption_menu_label.grid(row=0, column=0, sticky=W, padx=10, pady=5)

encryption_menu = OptionMenu(a, encryption_var, *encryption_options)
encryption_menu.grid(row=0, column=1, sticky=W, padx=10, pady=5)

# Source file selection
source_file_label = Label(a, text="Selected Source File: None")
source_file_label.grid(row=1, column=0, columnspan=2, sticky=W, padx=10, pady=5)

button1 = Button(a, text="Select Source file", width=30, command=mfileSourceopen)
button1.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

# Destination file selection
destination_file_label = Label(a, text="Selected Destination File: None")
destination_file_label.grid(row=3, column=0, columnspan=2, sticky=W, padx=10, pady=5)

button2 = Button(a, text="Select Destination File", width=30, command=mfileDestinationopen)
button2.grid(row=4, column=0, columnspan=2, padx=10, pady=5)

# Encryption button
encrypt_button_label = Label(a, text="Encrypt File:")
encrypt_button_label.grid(row=5, column=0, sticky=W, padx=10, pady=5)

button3 = Button(a, text="Encrypt", width=15, command=Encrypt, bg="lightblue", fg="black")
button3.grid(row=5, column=1, sticky=W, padx=10, pady=5)

# Decryption method selection
decryption_menu_label = Label(a, text="Decryption Method:")
decryption_menu_label.grid(row=6, column=0, sticky=W, padx=10, pady=5)

decryption_menu = OptionMenu(a, decryption_var, *encryption_options)
decryption_menu.grid(row=6, column=1, sticky=W, padx=10, pady=5)

# Decryption button
decrypt_button_label = Label(a, text="Decrypt File:")
decrypt_button_label.grid(row=7, column=0, sticky=W, padx=10, pady=5)

button4 = Button(a, text="Decrypt", width=15, command=Decrypt, bg="lightblue", fg="black")
button4.grid(row=7, column=1, sticky=W, padx=10, pady=5)

a.mainloop()
