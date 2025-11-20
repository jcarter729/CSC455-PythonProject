from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


def derive_key_from_password(password: str, salt: bytes = b"stream_salt") -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2-HMAC-SHA256."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    return PBKDF2(password, salt, dkLen=32, count=200_000, hmac_hash_module=SHA256)


def load_key_from_file(path: str = "secret.txt") -> bytes:
    """Load a passphrase from a file and derive a 32-byte key.

    For demo purposes we treat the file contents as a passphrase and derive a key.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            pw = fh.read().strip()
            if not pw:
                raise ValueError("Empty secret.txt")
    except Exception:
        # Fallback to a random key (not secure across runs)
        return get_random_bytes(32)
    return derive_key_from_password(pw)


def encrypt_frame(plain: bytes, key: bytes) -> bytes:
    """Encrypt bytes with AES-GCM and return nonce||tag||ciphertext."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    return nonce + tag + ciphertext


def decrypt_frame(packet: bytes, key: bytes) -> bytes:
    """Decrypt a packet produced by encrypt_frame and return plaintext.

    Packet layout: 12-byte nonce, 16-byte tag, remaining ciphertext.
    """
    if len(packet) < 28:
        raise ValueError("Packet too small to contain nonce+tag")
    nonce = packet[:12]
    tag = packet[12:28]
    ciphertext = packet[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    return plain
