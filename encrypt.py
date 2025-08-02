# encryption.py

import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 16
PBKDF2_ITERATIONS = 100_000
VERSION_HEADER = "AES256GCMv1"


def derive_key(
    password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS
) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_string(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    data = {
        "version": VERSION_HEADER,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

    json_data = json.dumps(data).encode("utf-8")
    return base64.b64encode(json_data).decode("utf-8")


def decrypt_string(base64_input: str, password: str) -> str | None:
    try:
        json_bytes = base64.b64decode(base64_input)
        data = json.loads(json_bytes.decode("utf-8"))

        if data.get("version") != VERSION_HEADER:
            return None

        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        tag = base64.b64decode(data["tag"])
        ciphertext = base64.b64decode(data["ciphertext"])

        key = derive_key(password, salt)
        cipher = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext_bytes.decode("utf-8")

    except (InvalidTag, ValueError, KeyError, json.JSONDecodeError):
        return None
