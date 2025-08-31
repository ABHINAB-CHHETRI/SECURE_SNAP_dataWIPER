import os
import shutil
from datetime import datetime

def wipe_file(file_path):
    try:
        if os.path.isfile(file_path):
            # Wipe a single file
            with open(file_path, "r+b") as f:
                length = f.seek(0, 2)  # Move to end to get size
                f.seek(0)
                f.write(b'\x00' * length)  # Overwrite with zeros
                f.flush()
            os.remove(file_path)  # Delete the file after wiping
            print(f"File wiped successfully: {file_path}")
            # Generate CLI certificate
            print("\n" + "="*50)
            print("          WIPE OPERATION CERTIFICATE")
            print("="*50)
            print(f"Path Wiped: {file_path}")
            print(f"Type: File")
            print(f"Date and Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("Status: Successfully wiped")
            print("="*50 + "\n")
        elif os.path.isdir(file_path):
            # Wipe a directory
            shutil.rmtree(file_path, ignore_errors=False)
            print(f"Directory wiped successfully: {file_path}")
            # Generate CLI certificate
            print("\n" + "="*50)
            print("          WIPE OPERATION CERTIFICATE")
            print("="*50)
            print(f"Path Wiped: {file_path}")
            print(f"Type: Directory")
            print(f"Date and Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("Status: Successfully wiped")
            print("="*50 + "\n")
        else:
            print(f"Path does not exist: {file_path}")
    except PermissionError as e:
        print(f"Permission denied: {e}")
    except Exception as e:
        print(f"Failed to wipe: {e}")

if __name__ == "__main__":
    path = input("Enter filepath to wipe: ")
    wipe_file(path)