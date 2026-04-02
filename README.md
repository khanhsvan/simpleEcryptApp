# Simple Encrypt App

Simple Encrypt App is a Tkinter desktop application for encrypting and decrypting files with five methods:

- ChaCha20-Poly1305 for fast, modern file protection with salted password-based security
- AES for general file encryption
- RSA with a hybrid RSA + AES format for larger files
- Caesar cipher for text files
- Playfair cipher for text files

## Requirements

- Python 3.10 or newer recommended
- Packages listed in `requirement.txt`

Install dependencies:

```bash
pip install -r requirement.txt
```

## Run the app

```bash
python app.py
```

## Recommended secure mode

The recommended method for most users is `ChaCha20-Poly1305`.

It now includes:

- authenticated encryption
- random salt and nonce per file
- `scrypt` password-based key derivation
- a versioned encrypted file format for future upgrades

Important:

- use a strong passphrase with at least 12 characters
- the passphrase is not stored in the encrypted file
- if the passphrase is weak, someone could still try offline password guessing

## Other methods

- `AES`: supports binary files and stores the IV in the output file
- `RSA`: automatically creates keys in the local `keys/` folder when needed
- `Caesar` and `Playfair`: included for learning and simple text use, not for strong real-world security

## Project structure

- `app.py`: app launcher
- `simple_encrypt_app/constants.py`: shared labels and method options
- `simple_encrypt_app/file_utils.py`: file read/write helpers
- `simple_encrypt_app/crypto_utils.py`: encryption algorithms and secure format handling
- `simple_encrypt_app/services.py`: encryption and decryption workflow
- `simple_encrypt_app/ui.py`: Tkinter interface

## Customer-facing improvements

- simpler step-by-step layout
- one action selector for encrypt or decrypt
- one method selector with guidance text
- clearer success and error messages
- activity log inside the app

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
