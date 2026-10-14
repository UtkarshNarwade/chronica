"""Cryptographic hashing utilities for digital evidence preservation.

Provides SHA-256 calculation over raw bytes, file paths, and file streams
using chunked reads to handle arbitrarily large logs without excessive memory consumption.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Union

DEFAULT_CHUNK_SIZE = 65536  # 64 KB


def calculate_sha256_bytes(data: bytes) -> str:
    """Calculate the hexadecimal SHA-256 digest of in-memory bytes."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def calculate_sha256_stream(stream: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Calculate SHA-256 digest from a readable binary stream.
    
    Streams chunk by chunk to prevent loading large files entirely into RAM.
    Does not close the stream.
    """
    hasher = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        hasher.update(chunk)
    return hasher.hexdigest()


def calculate_sha256_file(file_path: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Calculate the hexadecimal SHA-256 digest of an on-disk file.
    
    Args:
        file_path: Path to the target file.
        chunk_size: Size of chunks read in bytes.
        
    Returns:
        Hexadecimal SHA-256 digest string.
        
    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()
