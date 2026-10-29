import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Directory settings
KEYS_DIR = BASE_DIR / "keys"
RECEIVED_FILES_DIR = BASE_DIR / "received_files"

# Ensure directories exist
KEYS_DIR.mkdir(exist_ok=True)
RECEIVED_FILES_DIR.mkdir(exist_ok=True)

# RSA Key Paths
PRIVATE_KEY_PATH = KEYS_DIR / "receiver_private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "receiver_public.pem"

# Networking Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
CHUNK_SIZE = 64 * 1024  # 64 KB chunks for socket transfer
SOCKET_TIMEOUT = 15.0   # seconds

# Cryptographic Constants
RSA_KEY_SIZE = 2048     # 2048-bit RSA key pair
AES_KEY_SIZE = 32       # 256-bit AES key (32 bytes)
GCM_NONCE_SIZE = 12     # 96-bit nonce for AES-GCM (12 bytes)
GCM_TAG_SIZE = 16       # 128-bit authentication tag (16 bytes)

# Authentication Configuration (Default Demo Credentials)
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "securepassword123"

# Protocol Version
PROTOCOL_VERSION = "SWFS/1.0"
