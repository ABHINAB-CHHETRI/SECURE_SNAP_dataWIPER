import os
import secrets
import sys
from typing import BinaryIO

def schneier_wipe(file_handle: BinaryIO, block_size: int = 4096) -> bool:
    """
    Implements Bruce Schneier's 7-pass secure wiping technique
    Args:
        file_handle: Open file handle in binary write mode
        block_size: Size of blocks to write at once (default 4096 bytes)
    Returns:
        bool: True if wiping successful, False otherwise
    """
    try:
        # Get file size
        file_handle.seek(0, os.SEEK_END)
        file_size = file_handle.tell()
        
        # First pass - all zeros
        file_handle.seek(0)
        zero_block = b'\x00' * block_size
        for _ in range(0, file_size, block_size):
            remaining = min(block_size, file_size - file_handle.tell())
            file_handle.write(zero_block[:remaining])
        file_handle.flush()
        os.fsync(file_handle.fileno())

        # Second pass - all ones
        file_handle.seek(0)
        ones_block = b'\xff' * block_size
        for _ in range(0, file_size, block_size):
            remaining = min(block_size, file_size - file_handle.tell())
            file_handle.write(ones_block[:remaining])
        file_handle.flush()
        os.fsync(file_handle.fileno())

        # Passes 3-7 - random data
        for pass_num in range(5):
            file_handle.seek(0)
            for _ in range(0, file_size, block_size):
                remaining = min(block_size, file_size - file_handle.tell())
                random_block = secrets.token_bytes(remaining)
                file_handle.write(random_block)
            file_handle.flush()
            os.fsync(file_handle.fileno())

        return True

    except Exception as e:
        print(f"Error during secure wiping: {str(e)}", file=sys.stderr)
        return False

def verify_wipe(file_handle: BinaryIO, block_size: int = 4096) -> bool:
    """
    Verifies that the file contains no recoverable data
    Args:
        file_handle: Open file handle in binary read mode
        block_size: Size of blocks to read at once
    Returns:
        bool: True if verification successful
    """
    try:
        file_handle.seek(0)
        while True:
            block = file_handle.read(block_size)
            if not block:
                break
            # Check if block contains any non-zero data
            if any(b != 0 for b in block):
                return False
        return True
    except Exception as e:
        print(f"Error during verification: {str(e)}", file=sys.stderr)
        return False