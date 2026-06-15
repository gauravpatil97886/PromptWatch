from pathlib import Path
from cryptography.fernet import Fernet


def _load_or_create_key(key_file: Path) -> bytes:
    if key_file.exists():
        return key_file.read_bytes()
    key = Fernet.generate_key()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    return key


class Encryptor:
    def __init__(self, key_file: Path):
        self._fernet = Fernet(_load_or_create_key(key_file))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()
