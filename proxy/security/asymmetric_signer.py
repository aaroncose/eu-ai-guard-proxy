import os
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization

KEY_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "audit_signer_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "audit_signer_public.pem"

def ensure_signing_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

def sign_manifest_payload(payload_bytes: bytes) -> bytes:
    private_key, _ = ensure_signing_key_pair()
    return private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))

def sign_digest_directly(digest_bytes: bytes) -> bytes:
    """Firma directamente los 32 bytes del hash SHA-256 usando Prehashed."""
    private_key, _ = ensure_signing_key_pair()
    return private_key.sign(digest_bytes, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

def verify_manifest_signature(payload_bytes: bytes, signature_bytes: bytes) -> bool:
    _, public_key = ensure_signing_key_pair()
    try:
        public_key.verify(signature_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def get_public_key_pem() -> str:
    _, public_key = ensure_signing_key_pair()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")