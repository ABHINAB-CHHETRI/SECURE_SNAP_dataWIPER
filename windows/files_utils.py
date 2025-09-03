import os
import hashlib
from typing import List, Tuple
from ctypes import windll

def make_writable(path: str):
    """
    Make a file writable by changing its permissions.
    Args:
        path: Path to the file
    """
    try:
        os.chmod(path, 0o666)
    except Exception as e:
        print(f"Failed to change permissions for {path}: {e}")

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def verify_wipe(file_handle) -> bool:
    """
    Verifies that the file contains no recoverable data
    Args:
        file_handle: Open file handle in binary read mode
    Returns:
        bool: True if verification successful
    """
    try:
        file_handle.seek(0)
        while True:
            block = file_handle.read(8192)
            if not block:
                break
            # Check if block contains any non-zero data
            if any(b != 0 for b in block):
                return False
        return True
    except Exception as e:
        print(f"Error during verification: {str(e)}")
        return False
    finally:
        try:
            file_handle.seek(0)  # Reset file position after verification
        except Exception:
            pass  # Ignore errors in seek during cleanup

def secure_wipe_file(path: str, passes: int = 3, progress_callback=None, verify: bool = True) -> bool:
    """
    Overwrite file contents with random bytes for `passes` times, then remove it.
    NOTE: destructive.
    
    Args:
        path: Path to the file to wipe
        passes: Number of overwrite passes
        progress_callback: Optional callback function that accepts a pass number (1 to passes)
        verify: Whether to verify the wipe after completion
    Returns:
        bool: True if wipe and verification successful
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    make_writable(path)  # Ensure file is writable before wiping
        
    length = os.path.getsize(path)
    if length == 0:
        os.remove(path)
        return True
        
    # Open in rb+ mode where possible
    try:
        with open(path, "rb+") as f:
            for current_pass in range(1, passes + 1):
                f.seek(0)
                # Write in chunks to avoid memory blowup
                remaining = length
                CHUNK = 1024 * 1024
                while remaining > 0:
                    to_write = os.urandom(min(CHUNK, remaining))
                    f.write(to_write)
                    remaining -= len(to_write)
                f.flush()
                os.fsync(f.fileno())
                
                if progress_callback:
                    progress_callback(current_pass)
            
            # Verify the wipe if requested
            if verify:
                # Final pass - all zeros for verification
                f.seek(0)
                remaining = length
                while remaining > 0:
                    to_write = b'\x00' * min(CHUNK, remaining)
                    f.write(to_write)
                    remaining -= len(to_write)
                f.flush()
                os.fsync(f.fileno())
                
                # Verify the wipe
                verified = verify_wipe(f)
                if not verified:
                    f.close()
                    return False
            
        # Now that the file is properly closed, we can delete it
        try:
            os.remove(path)
            return True
        except Exception as e:
            print(f"Error deleting file {path}: {str(e)}")
            return False
            
    except Exception as e:
        print(f"Error during secure wipe of {path}: {str(e)}")
        return False
                    
    except PermissionError:
        raise PermissionError(f"Access denied to file: {path}")
    except OSError as e:
        # fallback: overwrite via writing to temporary then rename (best-effort)
        make_writable(path)  # Ensure writable before fallback
        with open(path, "wb") as f:
            for current_pass in range(1, passes + 1):
                f.seek(0)
                remaining = length
                CHUNK = 1024 * 1024
                while remaining > 0:
                    to_write = os.urandom(min(CHUNK, remaining))
                    f.write(to_write)
                    remaining -= len(to_write)
                f.flush()
                os.fsync(f.fileno())
                
                if progress_callback:
                    progress_callback(current_pass)
    # remove file
    os.remove(path)

def is_hidden_windows(filepath: str) -> bool:
    """
    Check if a file is hidden on Windows using GetFileAttributes
    """
    try:
        attrs = windll.kernel32.GetFileAttributesW(filepath)
        return attrs != -1 and bool(attrs & 2)  # 2 is FILE_ATTRIBUTE_HIDDEN
    except Exception:
        return False

def collect_files(folder_path: str) -> Tuple[List[str], int, int]:
    file_paths = []
    total_size = 0
    hidden_files = 0
    
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_paths.append(file_path)
            try:
                total_size += os.path.getsize(file_path)
                # Check for Windows hidden files using proper API
                if is_hidden_windows(file_path):
                    hidden_files += 1
            except Exception as e:
                print(f"Error processing file {file_path}: {str(e)}")
                pass
                
    return file_paths, total_size, hidden_files