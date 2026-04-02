APP_TITLE = "Simple Encrypt App"
ENCRYPTION_OPTIONS = ["ChaCha20-Poly1305", "AES", "RSA", "Caesar", "Playfair"]
RSA_MAGIC = b"SEARSA1"
TEXT_ENCODING = "utf-8"

METHOD_DESCRIPTIONS = {
    "ChaCha20-Poly1305": "Recommended for speed. Modern authenticated encryption for text and binary files.",
    "AES": "Best for everyday file protection. Works with text and binary files.",
    "RSA": "Uses generated keys. Great when you want private/public key security.",
    "Caesar": "Basic text-only cipher for simple demos and learning.",
    "Playfair": "Classic text-only cipher for alphabet-based messages.",
}
