import hashlib
import os
import secrets
from typing import Tuple, Dict

# User authentication store (username -> salt_hex, hash_hex)
# Uses PBKDF2-HMAC-SHA256 with 100,000 iterations for secure password hashing.
_USER_DB: Dict[str, Tuple[str, str]] = {}

def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
    """
    Hashes a password using PBKDF2-HMAC-SHA256.
    If no salt is provided, generates a new 16-byte random salt.
    Returns: (salt_hex, hash_hex)
    """
    if salt is None:
        salt = os.urandom(16)
    
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations=100000
    )
    return salt.hex(), derived_key.hex()

def verify_password(stored_salt_hex: str, stored_hash_hex: str, provided_password: str) -> bool:
    """
    Verifies a provided password against stored salt and hash in constant time.
    """
    salt = bytes.fromhex(stored_salt_hex)
    _, new_hash_hex = hash_password(provided_password, salt)
    return secrets.compare_digest(stored_hash_hex, new_hash_hex)

def register_user(username: str, password: str) -> None:
    """Registers a new user in the memory user store with salted password hash."""
    salt_hex, hash_hex = hash_password(password)
    _USER_DB[username] = (salt_hex, hash_hex)

def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticates a user against the user store.
    Returns True if username exists and password matches, False otherwise.
    """
    if username not in _USER_DB:
        return False
    salt_hex, hash_hex = _USER_DB[username]
    return verify_password(salt_hex, hash_hex, password)

# Initialize default demo user
register_user("admin", "securepassword123")
register_user("student", "viva2026")
