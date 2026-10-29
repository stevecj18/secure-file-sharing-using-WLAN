import socket
import json
import struct
import os
import re
from pathlib import Path
from typing import Dict, Any, Optional

import config

def get_local_ip() -> str:
    """
    Attempts to discover the computer's local IPv4 address on the active WLAN/LAN.
    Falls back to 127.0.0.1 if network is unavailable.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually transmit data, but forces OS to pick primary network route IP
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def send_json_message(sock: socket.socket, data: Dict[str, Any]) -> None:
    """
    Packs a Python dictionary as UTF-8 JSON with a 4-byte big-endian length prefix
    and sends it over the socket.
    """
    json_bytes = json.dumps(data).encode('utf-8')
    header = struct.pack('>I', len(json_bytes))
    sock.sendall(header + json_bytes)

def recv_json_message(sock: socket.socket) -> Dict[str, Any]:
    """
    Reads a 4-byte big-endian length prefix, then receives the full JSON message payload.
    Returns decoded Python dictionary.
    """
    header = recv_exact(sock, 4)
    if not header:
        raise ConnectionError("Socket closed while reading message header")
    length = struct.unpack('>I', header)[0]
    payload = recv_exact(sock, length)
    if not payload:
        raise ConnectionError("Socket closed while reading message payload")
    return json.loads(payload.decode('utf-8'))

def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Reliably reads exactly num_bytes from socket, handling partial TCP reads.
    Raises ConnectionError if connection closes prematurely.
    """
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(min(num_bytes - len(buffer), 65536))
        if not chunk:
            raise ConnectionError(f"Connection closed after receiving {len(buffer)}/{num_bytes} bytes")
        buffer.extend(chunk)
    return bytes(buffer)

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes filename to prevent path traversal attacks (e.g. ../../etc/passwd).
    Strips directory paths, drive letters, and dangerous characters.
    """
    # Extract only the base name of the path
    clean_name = os.path.basename(filename)
    # Remove drive letters if on Windows (e.g., C:\)
    clean_name = re.sub(r'^[a-zA-Z]:', '', clean_name)
    # Replace invalid characters
    clean_name = re.sub(r'[^\w\s\.-]', '_', clean_name).strip()
    if not clean_name:
        clean_name = "unnamed_file.bin"
    return clean_name

def get_safe_filepath(directory: Path, filename: str) -> Path:
    """
    Ensures unique filename in destination directory to prevent overwriting existing files.
    If file.png exists, generates file_1.png, file_2.png, etc.
    """
    sanitized = sanitize_filename(filename)
    target_path = directory / sanitized
    if not target_path.exists():
        return target_path

    stem = target_path.stem
    suffix = target_path.suffix
    counter = 1
    while True:
        candidate = directory / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1
