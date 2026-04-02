from pathlib import Path
from typing import Callable

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


ProgressCallback = Callable[[float, str], None]


def report_progress(callback: ProgressCallback | None, value: float, message: str) -> None:
    if callback is not None:
        callback(value, message)


def encrypt_with_method(
    method: str,
    source: str,
    destination: str,
    secret: str,
    base_dir: Path,
    progress_callback: ProgressCallback | None = None,
) -> str:
    ensure_destination_directory(destination)
    report_progress(progress_callback, 10, "Preparing destination...")

    if method == "ChaCha20-Poly1305":
        if not validate_passphrase(secret):
            raise ValueError("ChaCha20-Poly1305 needs a passphrase with at least 12 characters.")
        report_progress(progress_callback, 30, "Reading source file...")
        source_data = read_binary_file(source)
        report_progress(progress_callback, 65, "Encrypting with ChaCha20-Poly1305...")
        encrypted_data = chacha20_encrypt_bytes(source_data, secret)
        report_progress(progress_callback, 90, "Writing encrypted file...")
        write_binary_file(destination, encrypted_data)
        report_progress(progress_callback, 100, "Encryption complete.")
        return "ChaCha20-Poly1305 encryption complete. The file now uses salted scrypt key derivation and authenticated encryption."

    if method == "AES":
        if not validate_aes_key(secret):
            raise ValueError("AES key must be 16, 24, or 32 bytes when encoded as UTF-8.")
        report_progress(progress_callback, 30, "Reading source file...")
        source_data = read_binary_file(source)
        report_progress(progress_callback, 65, "Encrypting with AES...")
        encrypted_data = aes_encrypt_bytes(source_data, secret.encode(TEXT_ENCODING))
        report_progress(progress_callback, 90, "Writing encrypted file...")
        write_binary_file(destination, encrypted_data)
        report_progress(progress_callback, 100, "Encryption complete.")
        return "AES encryption complete. The IV is stored inside the encrypted output file."

    if method == "RSA":
        report_progress(progress_callback, 20, "Checking RSA key files...")
        private_key_path, public_key_path = ensure_rsa_key_pair(base_dir)
        report_progress(progress_callback, 35, "Reading source file...")
        source_data = read_binary_file(source)
        report_progress(progress_callback, 70, "Encrypting with RSA hybrid mode...")
        encrypted_data = rsa_encrypt_bytes(source_data, public_key_path)
        report_progress(progress_callback, 90, "Writing encrypted file...")
        write_binary_file(destination, encrypted_data)
        report_progress(progress_callback, 100, "Encryption complete.")
        return f"RSA encryption complete. Key files are available in {private_key_path.parent}."

    if method == "Caesar":
        report_progress(progress_callback, 30, "Reading source file...")
        source_text = read_text_file(source)
        report_progress(progress_callback, 65, "Encrypting text with Caesar...")
        encrypted_text = caesar_encrypt(source_text, int(secret))
        report_progress(progress_callback, 90, "Writing encrypted file...")
        write_text_file(destination, encrypted_text)
        report_progress(progress_callback, 100, "Encryption complete.")
        return "Caesar encryption complete."

    if method == "Playfair":
        report_progress(progress_callback, 30, "Reading source file...")
        source_text = read_text_file(source)
        report_progress(progress_callback, 65, "Encrypting text with Playfair...")
        encrypted_text = playfair_encrypt(source_text, secret)
        report_progress(progress_callback, 90, "Writing encrypted file...")
        write_text_file(destination, encrypted_text)
        report_progress(progress_callback, 100, "Encryption complete.")
        return "Playfair encryption complete. Non-letter characters are removed during processing."

    raise ValueError("Unsupported encryption method.")


def decrypt_with_method(
    method: str,
    source: str,
    destination: str,
    secret: str,
    progress_callback: ProgressCallback | None = None,
) -> str:
    ensure_destination_directory(destination)
    report_progress(progress_callback, 10, "Preparing destination...")

    if method == "ChaCha20-Poly1305":
        if not validate_passphrase(secret):
            raise ValueError("ChaCha20-Poly1305 needs a passphrase with at least 12 characters.")
        report_progress(progress_callback, 30, "Reading encrypted file...")
        source_data = read_binary_file(source)
        report_progress(progress_callback, 65, "Decrypting with ChaCha20-Poly1305...")
        decrypted_data = chacha20_decrypt_bytes(source_data, secret)
        report_progress(progress_callback, 90, "Writing unlocked file...")
        write_binary_file(destination, decrypted_data)
        report_progress(progress_callback, 100, "Decryption complete.")
        return "ChaCha20-Poly1305 decryption complete."

    if method == "AES":
        if not validate_aes_key(secret):
            raise ValueError("AES key must be 16, 24, or 32 bytes when encoded as UTF-8.")
        report_progress(progress_callback, 30, "Reading encrypted file...")
        source_data = read_binary_file(source)
        report_progress(progress_callback, 65, "Decrypting with AES...")
        decrypted_data = aes_decrypt_bytes(source_data, secret.encode(TEXT_ENCODING))
        report_progress(progress_callback, 90, "Writing unlocked file...")
        write_binary_file(destination, decrypted_data)
        report_progress(progress_callback, 100, "Decryption complete.")
        return "AES decryption complete."

    if method == "RSA":
        report_progress(progress_callback, 30, "Reading encrypted file...")
        source_data = read_binary_file(source)
        report_progress(progress_callback, 65, "Decrypting with RSA hybrid mode...")
        decrypted_data = rsa_decrypt_bytes(source_data, secret)
        report_progress(progress_callback, 90, "Writing unlocked file...")
        write_binary_file(destination, decrypted_data)
        report_progress(progress_callback, 100, "Decryption complete.")
        return "RSA decryption complete."

    if method == "Caesar":
        report_progress(progress_callback, 30, "Reading encrypted file...")
        source_text = read_text_file(source)
        report_progress(progress_callback, 65, "Decrypting text with Caesar...")
        decrypted_text = caesar_decrypt(source_text, int(secret))
        report_progress(progress_callback, 90, "Writing unlocked file...")
        write_text_file(destination, decrypted_text)
        report_progress(progress_callback, 100, "Decryption complete.")
        return "Caesar decryption complete."

    if method == "Playfair":
        report_progress(progress_callback, 30, "Reading encrypted file...")
        source_text = read_text_file(source)
        report_progress(progress_callback, 65, "Decrypting text with Playfair...")
        decrypted_text = playfair_decrypt(source_text, secret)
        report_progress(progress_callback, 90, "Writing unlocked file...")
        write_text_file(destination, decrypted_text)
        report_progress(progress_callback, 100, "Decryption complete.")
        return "Playfair decryption complete."

    raise ValueError("Unsupported decryption method.")
