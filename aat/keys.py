from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


KEY_DIR = Path("keys")


def generate_key_pair(name):
    KEY_DIR.mkdir(exist_ok=True)

    private_path = KEY_DIR / f"{name}-private.pem"
    public_path = KEY_DIR / f"{name}-public.pem"

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)

    return private_key, public_key


def load_private_key(name):
    path = KEY_DIR / f"{name}-private.pem"

    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )


def load_public_key(name):
    path = KEY_DIR / f"{name}-public.pem"

    return serialization.load_pem_public_key(
        path.read_bytes()
    )
