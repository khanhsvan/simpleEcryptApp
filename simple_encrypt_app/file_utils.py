from pathlib import Path

from .constants import TEXT_ENCODING


def read_text_file(path: str) -> str:
    with open(path, "r", encoding=TEXT_ENCODING) as file:
        return file.read()


def read_binary_file(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def write_binary_file(path: str, data: bytes) -> None:
    with open(path, "wb") as file:
        file.write(data)


def write_text_file(path: str, data: str) -> None:
    with open(path, "w", encoding=TEXT_ENCODING) as file:
        file.write(data)


def ensure_destination_directory(path: str) -> None:
    Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
