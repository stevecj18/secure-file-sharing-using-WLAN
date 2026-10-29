import os
import hashlib
import warnings
from typing import Tuple, Optional
from pathlib import Path

warnings.filterwarnings("ignore", message=".*Python 3.8 is no longer supported.*")

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag, InvalidSignature

import config

def generate_rsa_keypair(key_size: int = config.RSA_KEY_SIZE) -> Tuple[bytes, bytes]:
    """
    Generates an RSA private/public key pair.
    Returns: (private_key_pem_bytes, public_key_pem_bytes)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def save_keypair_to_disk(private_pem: bytes, public_pem: bytes,
                         private_path: Path = config.PRIVATE_KEY_PATH,
                         public_path: Path = config.PUBLIC_KEY_PATH) -> None:
    """Saves the RSA keypair to specified file paths."""
    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)

def load_or_create_rsa_keys(private_path: Path = config.PRIVATE_KEY_PATH,
                            public_path: Path = config.PUBLIC_KEY_PATH) -> Tuple[bytes, bytes]:
    """
    Loads RSA keys from disk if present, otherwise generates and saves a new pair.
    Returns: (private_key_pem_bytes, public_key_pem_bytes)
    """
    if private_path.exists() and public_path.exists():
        with open(private_path, "rb") as f:
            private_pem = f.read()
        with open(public_path, "rb") as f:
            public_pem = f.read()
        return private_pem, public_pem
    else:
        private_pem, public_pem = generate_rsa_keypair()
        save_keypair_to_disk(private_pem, public_pem, private_path, public_path)
        return private_pem, public_pem

def encrypt_aes_key_rsa(public_key_pem: bytes, aes_key: bytes) -> bytes:
    """
    Encrypts a 256-bit AES session key using the receiver's RSA Public Key with RSA-OAEP padding.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_aes_key_rsa(private_key_pem: bytes, encrypted_aes_key: bytes) -> bytes:
    """
    Decrypts an RSA-OAEP encrypted AES session key using the receiver's RSA Private Key.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def generate_aes_key() -> bytes:
    """Generates a cryptographically secure 256-bit (32-byte) AES session key."""
    return os.urandom(config.AES_KEY_SIZE)

def generate_gcm_nonce() -> bytes:
    """Generates a cryptographically secure 96-bit (12-byte) AES-GCM nonce."""
    return os.urandom(config.GCM_NONCE_SIZE)

def calculate_sha256(file_path: str) -> str:
    """
    Calculates the SHA-256 hash digest of a file reading in chunks.
    Returns hex string digest.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(config.CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def calculate_bytes_sha256(data: bytes) -> str:
    """Calculates SHA-256 hash digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()

class StreamingAESGCMEncryptor:
    """
    Helper class for streaming AES-GCM encryption of file chunks.
    Computes ciphertext stream and final 16-byte authentication tag.
    """
    def __init__(self, aes_key: bytes, nonce: bytes):
        self.aes_key = aes_key
        self.nonce = nonce
        self.cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        self.encryptor = self.cipher.encryptor()

    def update(self, chunk: bytes) -> bytes:
        return self.encryptor.update(chunk)

    def finalize(self) -> Tuple[bytes, bytes]:
        """
        Finalizes encryption.
        Returns: (final_ciphertext_chunk, auth_tag_16_bytes)
        """
        final_chunk = self.encryptor.finalize()
        tag = self.encryptor.tag
        return final_chunk, tag

class StreamingAESGCMDecryptor:
    """
    Helper class for streaming AES-GCM decryption of file chunks.
    Verifies authentication tag on finalize().
    """
    def __init__(self, aes_key: bytes, nonce: bytes, tag: bytes):
        self.aes_key = aes_key
        self.nonce = nonce
        self.tag = tag
        self.cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
        self.decryptor = self.cipher.decryptor()

    def update(self, chunk: bytes) -> bytes:
        return self.decryptor.update(chunk)

    def finalize(self) -> bytes:
        """
        Finalizes decryption and validates AES-GCM authentication tag.
        Raises InvalidTag if tag or ciphertext has been tampered with.
        """
        return self.decryptor.finalize()
