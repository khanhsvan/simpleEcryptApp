import struct
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .constants import RSA_MAGIC, TEXT_ENCODING
from .file_utils import read_binary_file


CHACHA_MAGIC = b"SEACHA1"
CHACHA_SALT_LENGTH = 16
CHACHA_NONCE_LENGTH = 12
CHACHA_KEY_LENGTH = 32
CHACHA_SCRYPT_N = 2**14
CHACHA_SCRYPT_R = 8
CHACHA_SCRYPT_P = 1


def validate_aes_key(key: str) -> bool:
    return len(key.encode(TEXT_ENCODING)) in (16, 24, 32)


def validate_passphrase(passphrase: str) -> bool:
    return bool(passphrase and len(passphrase.strip()) >= 12)


def derive_chacha_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=CHACHA_KEY_LENGTH,
        n=CHACHA_SCRYPT_N,
        r=CHACHA_SCRYPT_R,
        p=CHACHA_SCRYPT_P,
    )
    return kdf.derive(passphrase.encode(TEXT_ENCODING))


def pad_bytes(data: bytes) -> bytes:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()


def unpad_bytes(data: bytes) -> bytes:
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aes_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad_bytes(data)) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt_bytes(payload: bytes, key: bytes) -> bytes:
    if len(payload) <= 16:
        raise ValueError("Encrypted AES file is too short to contain an IV.")

    iv = payload[:16]
    ciphertext = payload[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_bytes(padded_plaintext)


def chacha20_encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    salt = get_random_bytes(CHACHA_SALT_LENGTH)
    nonce = get_random_bytes(CHACHA_NONCE_LENGTH)
    key = derive_chacha_key(passphrase, salt)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, data, None)
    header = (
        CHACHA_MAGIC
        + struct.pack(">I", CHACHA_SCRYPT_N)
        + struct.pack(">I", CHACHA_SCRYPT_R)
        + struct.pack(">I", CHACHA_SCRYPT_P)
        + salt
        + nonce
    )
    return header + ciphertext


def chacha20_decrypt_bytes(payload: bytes, passphrase: str) -> bytes:
    minimum_size = len(CHACHA_MAGIC) + 12 + CHACHA_SALT_LENGTH + CHACHA_NONCE_LENGTH + 16
    if len(payload) < minimum_size:
        raise ValueError("Encrypted ChaCha20 file is too short or incomplete.")
    if not payload.startswith(CHACHA_MAGIC):
        raise ValueError("This file is not in the app's ChaCha20-Poly1305 format.")

    offset = len(CHACHA_MAGIC)
    scrypt_n = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    scrypt_r = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    scrypt_p = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    salt = payload[offset:offset + CHACHA_SALT_LENGTH]
    offset += CHACHA_SALT_LENGTH
    nonce = payload[offset:offset + CHACHA_NONCE_LENGTH]
    offset += CHACHA_NONCE_LENGTH
    ciphertext = payload[offset:]

    kdf = Scrypt(
        salt=salt,
        length=CHACHA_KEY_LENGTH,
        n=scrypt_n,
        r=scrypt_r,
        p=scrypt_p,
    )
    key = kdf.derive(passphrase.encode(TEXT_ENCODING))
    cipher = ChaCha20Poly1305(key)

    try:
        return cipher.decrypt(nonce, ciphertext, None)
    except InvalidTag as error:
        raise ValueError("Decryption failed. The passphrase may be incorrect or the file may be damaged.") from error


def ensure_rsa_key_pair(base_dir: Path) -> tuple[Path, Path]:
    keys_dir = base_dir / "keys"
    keys_dir.mkdir(exist_ok=True)
    private_key_path = keys_dir / "privatekey.pem"
    public_key_path = keys_dir / "publickey.pem"

    if not private_key_path.exists() or not public_key_path.exists():
        key = RSA.generate(2048)
        private_key_path.write_bytes(key.export_key())
        public_key_path.write_bytes(key.publickey().export_key())

    return private_key_path, public_key_path


def rsa_encrypt_bytes(data: bytes, public_key_path: Path) -> bytes:
    recipient_key = RSA.import_key(public_key_path.read_bytes())
    rsa_cipher = PKCS1_OAEP.new(recipient_key)
    session_key = get_random_bytes(32)
    encrypted_session_key = rsa_cipher.encrypt(session_key)
    aes_payload = aes_encrypt_bytes(data, session_key)
    return RSA_MAGIC + struct.pack(">H", len(encrypted_session_key)) + encrypted_session_key + aes_payload


def rsa_decrypt_bytes(payload: bytes, private_key_path: str) -> bytes:
    if not payload.startswith(RSA_MAGIC):
        raise ValueError("This file is not in the app's RSA encrypted format.")

    offset = len(RSA_MAGIC)
    encrypted_key_length = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    encrypted_session_key = payload[offset:offset + encrypted_key_length]
    offset += encrypted_key_length
    aes_payload = payload[offset:]

    private_key = RSA.import_key(read_binary_file(private_key_path))
    rsa_cipher = PKCS1_OAEP.new(private_key)
    session_key = rsa_cipher.decrypt(encrypted_session_key)
    return aes_decrypt_bytes(aes_payload, session_key)


def caesar_encrypt(plaintext: str, key: int) -> str:
    encrypted_text = []
    for char in plaintext:
        if char.isalpha():
            start = ord("a") if char.islower() else ord("A")
            encrypted_text.append(chr((ord(char) - start + key) % 26 + start))
        else:
            encrypted_text.append(char)
    return "".join(encrypted_text)


def caesar_decrypt(ciphertext: str, key: int) -> str:
    return caesar_encrypt(ciphertext, -key)


def prepare_playfair_key(key: str) -> str:
    sanitized_key = "".join(char for char in key.upper() if char.isalpha()).replace("J", "I")
    unique_chars = "".join(dict.fromkeys(sanitized_key))
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in unique_chars:
        alphabet = alphabet.replace(char, "")
    return unique_chars + alphabet


def normalize_playfair_text(text: str) -> str:
    return "".join(char for char in text.upper() if char.isalpha()).replace("J", "I")


def build_playfair_pairs(text: str) -> list[str]:
    normalized = normalize_playfair_text(text)
    pairs = []
    index = 0

    while index < len(normalized):
        first = normalized[index]
        second = normalized[index + 1] if index + 1 < len(normalized) else "X"

        if first == second:
            pairs.append(first + "X")
            index += 1
        else:
            pairs.append(first + second)
            index += 2

    return pairs


def transform_playfair_pair(pair: str, table: str, encrypt: bool) -> str:
    row1, col1 = divmod(table.index(pair[0]), 5)
    row2, col2 = divmod(table.index(pair[1]), 5)
    shift = 1 if encrypt else -1

    if row1 == row2:
        return table[row1 * 5 + (col1 + shift) % 5] + table[row2 * 5 + (col2 + shift) % 5]
    if col1 == col2:
        return table[((row1 + shift) % 5) * 5 + col1] + table[((row2 + shift) % 5) * 5 + col2]
    return table[row1 * 5 + col2] + table[row2 * 5 + col1]


def playfair_encrypt(plaintext: str, key: str) -> str:
    table = prepare_playfair_key(key)
    return "".join(transform_playfair_pair(pair, table, True) for pair in build_playfair_pairs(plaintext))


def playfair_decrypt(ciphertext: str, key: str) -> str:
    table = prepare_playfair_key(key)
    normalized = normalize_playfair_text(ciphertext)
    if len(normalized) % 2 != 0:
        normalized += "X"
    pairs = [normalized[index:index + 2] for index in range(0, len(normalized), 2)]
    return "".join(transform_playfair_pair(pair, table, False) for pair in pairs)
