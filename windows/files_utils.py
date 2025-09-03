import os
import hashlib
from typing import List, Tuple



def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()





def secure_wipe_file(path: str, passes: int = 3, progress_callback=None) -> None:
    """
    Overwrite file contents with random bytes for `passes` times, then remove it.
    NOTE: destructive.
    
    Args:
        path: Path to the file to wipe
        passes: Number of overwrite passes
        progress_callback: Optional callback function that accepts a pass number (1 to passes)
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
        
    length = os.path.getsize(path)
    if length == 0:
        os.remove(path)
        return
        
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
                    
    except PermissionError:
        raise PermissionError(f"Access denied to file: {path}")
    except OSError as e:
        # fallback: overwrite via writing to temporary then rename (best-effort)
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
                if file.startswith('.') or file.startswith('~'):
                    hidden_files += 1
            except Exception:
                pass
    return file_paths, total_size, hidden_files