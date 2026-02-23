import os, hmac, hashlib, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

AES_KEY_LEN = 32          # 256-bit AES key
IV_LEN = 16               # AES block size
HMAC_LEN = 32             # SHA-256 output

def _aes_cbc_encrypt(enc_key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def _aes_cbc_decrypt(enc_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def encrypt_then_mac(master_key: bytes, plaintext: bytes) -> bytes:
    """
    Returns payload: IV || ciphertext || hmac
    Uses simple key split: first 32 bytes for AES, next 32 bytes for HMAC.
    (For production, use HKDF. For class/lab, this is ok if master_key is strong.)
    """
    if len(master_key) < 64:
        raise ValueError("master_key must be at least 64 bytes (32 AES + 32 HMAC).")

    enc_key = master_key[:32]
    mac_key = master_key[32:64]

    iv = os.urandom(IV_LEN)
    ciphertext = _aes_cbc_encrypt(enc_key, iv, plaintext)

    tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv + ciphertext + tag

def verify_mac_then_decrypt(master_key: bytes, payload: bytes) -> bytes:
    if len(master_key) < 64:
        raise ValueError("master_key must be at least 64 bytes (32 AES + 32 HMAC).")

    if len(payload) < IV_LEN + HMAC_LEN:
        raise ValueError("payload too short")

    enc_key = master_key[:32]
    mac_key = master_key[32:64]

    iv = payload[:IV_LEN]
    tag = payload[-HMAC_LEN:]
    ciphertext = payload[IV_LEN:-HMAC_LEN]

    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("HMAC check failed (message modified or wrong key)")

    return _aes_cbc_decrypt(enc_key, iv, ciphertext)

def send_framed(sock, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)

def recv_exact(sock, n: int) -> bytes:
    chunks = []
    got = 0
    while got < n:
        chunk = sock.recv(n - got)
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)

def recv_framed(sock) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, length)