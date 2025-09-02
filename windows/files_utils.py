import os
import hashlib
from typing import List, Tuple



def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()





def secure_wipe_file(path: str, passes: int = 3) -> None:
    """
    Overwrite file contents with random bytes for `passes` times, then remove it.
    NOTE: destructive.
    """
    length = os.path.getsize(path)
    # Open in rb+ mode where possible
    try:
        with open(path, "rb+") as f:
            for _ in range(passes):
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
    except Exception:
        # fallback: overwrite via writing to temporary then rename (best-effort)
        with open(path, "wb") as f:
            remaining = length
            CHUNK = 1024 * 1024
            while remaining > 0:
                to_write = os.urandom(min(CHUNK, remaining))
                f.write(to_write)
                remaining -= len(to_write)
            f.flush()
            os.fsync(f.fileno())
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