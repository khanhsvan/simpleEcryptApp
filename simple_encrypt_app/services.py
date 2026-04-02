from pathlib import Path

from .constants import TEXT_ENCODING
from .crypto_utils import (
    aes_decrypt_bytes,
    aes_encrypt_bytes,
    caesar_decrypt,
    caesar_encrypt,
    chacha20_decrypt_bytes,
    chacha20_encrypt_bytes,
    ensure_rsa_key_pair,
    playfair_decrypt,
    playfair_encrypt,
    rsa_decrypt_bytes,
    rsa_encrypt_bytes,
    validate_aes_key,
    validate_passphrase,
)
from .file_utils import (
    ensure_destination_directory,
    read_binary_file,
    read_text_file,
    write_binary_file,
    write_text_file,
)


def encrypt_with_method(method: str, source: str, destination: str, secret: str, base_dir: Path) -> str:
    ensure_destination_directory(destination)

    if method == "ChaCha20-Poly1305":
        if not validate_passphrase(secret):
            raise ValueError("ChaCha20-Poly1305 needs a passphrase.")
        encrypted_data = chacha20_encrypt_bytes(read_binary_file(source), secret)
        write_binary_file(destination, encrypted_data)
        return "ChaCha20-Poly1305 encryption complete. This is the recommended fast option for everyday use."

    if method == "AES":
        if not validate_aes_key(secret):
            raise ValueError("AES key must be 16, 24, or 32 bytes when encoded as UTF-8.")
        encrypted_data = aes_encrypt_bytes(read_binary_file(source), secret.encode(TEXT_ENCODING))
        write_binary_file(destination, encrypted_data)
        return "AES encryption complete. The IV is stored inside the encrypted output file."

    if method == "RSA":
        private_key_path, public_key_path = ensure_rsa_key_pair(base_dir)
        encrypted_data = rsa_encrypt_bytes(read_binary_file(source), public_key_path)
        write_binary_file(destination, encrypted_data)
        return f"RSA encryption complete. Key files are available in {private_key_path.parent}."

    if method == "Caesar":
        encrypted_text = caesar_encrypt(read_text_file(source), int(secret))
        write_text_file(destination, encrypted_text)
        return "Caesar encryption complete."

    if method == "Playfair":
        encrypted_text = playfair_encrypt(read_text_file(source), secret)
        write_text_file(destination, encrypted_text)
        return "Playfair encryption complete. Non-letter characters are removed during processing."

    raise ValueError("Unsupported encryption method.")


def decrypt_with_method(method: str, source: str, destination: str, secret: str) -> str:
    ensure_destination_directory(destination)

    if method == "ChaCha20-Poly1305":
        if not validate_passphrase(secret):
            raise ValueError("ChaCha20-Poly1305 needs a passphrase.")
        decrypted_data = chacha20_decrypt_bytes(read_binary_file(source), secret)
        write_binary_file(destination, decrypted_data)
        return "ChaCha20-Poly1305 decryption complete."

    if method == "AES":
        if not validate_aes_key(secret):
            raise ValueError("AES key must be 16, 24, or 32 bytes when encoded as UTF-8.")
        decrypted_data = aes_decrypt_bytes(read_binary_file(source), secret.encode(TEXT_ENCODING))
        write_binary_file(destination, decrypted_data)
        return "AES decryption complete."

    if method == "RSA":
        decrypted_data = rsa_decrypt_bytes(read_binary_file(source), secret)
        write_binary_file(destination, decrypted_data)
        return "RSA decryption complete."

    if method == "Caesar":
        decrypted_text = caesar_decrypt(read_text_file(source), int(secret))
        write_text_file(destination, decrypted_text)
        return "Caesar decryption complete."

    if method == "Playfair":
        decrypted_text = playfair_decrypt(read_text_file(source), secret)
        write_text_file(destination, decrypted_text)
        return "Playfair decryption complete."

    raise ValueError("Unsupported decryption method.")
