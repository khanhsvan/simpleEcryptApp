# Simple Encrypt App

Simple Encrypt App is a Tkinter desktop application for encrypting and decrypting files with five methods:

- ChaCha20-Poly1305 for fast modern file protection
- AES for general file encryption
- RSA with a hybrid RSA + AES format for larger files
- Caesar cipher for text files
- Playfair cipher for text files

## Requirements

- Python 3.x
- Required packages from `requirement.txt`

Install dependencies:

```bash
pip install -r requirement.txt
```

## Run the app

```bash
python app.py
```

## Better structure

The app is now separated into smaller modules to make it easier to control and extend:

- `app.py`: small launcher
- `simple_encrypt_app/constants.py`: shared app text and options
- `simple_encrypt_app/file_utils.py`: file reading and writing helpers
- `simple_encrypt_app/crypto_utils.py`: encryption and decryption algorithms
- `simple_encrypt_app/services.py`: business flow for encrypting and decrypting files
- `simple_encrypt_app/ui.py`: customer-facing desktop interface

## Easier customer flow

- One clear action selector for Encrypt or Decrypt
- One method selector with plain-language guidance
- ChaCha20-Poly1305 is now the recommended fast option for most customers
- Step-by-step layout for choosing files and running the action
- Status messages and recent activity log inside the app
- Friendly popups for success and error states

## Notes

- ChaCha20-Poly1305 uses a passphrase and is the best default choice for speed and ease of use.
- AES keys must be 16, 24, or 32 bytes when encoded as UTF-8.
- Caesar and Playfair are text-only methods and are best used with plain text files.
- Playfair removes non-letter characters during encryption and decryption.
- RSA keys are generated automatically into the local `keys/` folder when needed.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
