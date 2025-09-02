import os
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

# Key files (demo, store securely in production)
PRIVATE_KEY_FILE = "cert_private_key.pem"
PUBLIC_KEY_FILE = "cert_public_key.pem"
def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def get_certificate_data(cert):
    # Remove signature_b64 and use indent=2, ensure_ascii=False for compatibility
    cert_data = dict(cert)
    cert_data.pop("signature_b64", None)
    return json.dumps(cert_data, indent=2, ensure_ascii=False).encode("utf-8")
def ensure_keypair(private_path: str = PRIVATE_KEY_FILE, public_path: str = PUBLIC_KEY_FILE):
    """
    Create RSA keypair if not present. Returns (private_key, public_key)
    """
    if os.path.exists(private_path):
        with open(private_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
        with open(private_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    if os.path.exists(public_path):
        with open(public_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    else:
        public_key = private_key.public_key()
        with open(public_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return private_key, public_key


def sign_json_bytes(data: bytes, private_key) -> str:
    sig = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode("ascii")

def verify_signature_bytes(data: bytes, signature_b64: str, public_key) -> bool:
    try:
        sig = base64.b64decode(signature_b64)
        public_key.verify(
            sig,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def verify_certificate_json(signed_json_path: str, public_key_path: str) -> bool:
    """
    Verifies signature embedded in signed JSON file produced by write_certificate_files.
    Returns True if valid.
    """
    with open(signed_json_path, "r", encoding="utf-8") as f:
        cert = json.load(f)
    signature_b64 = cert.get("signature_b64")
    # Create unsigned snapshot by removing signature_b64 before verification
    cert_unsigned = dict(cert)
    cert_unsigned.pop("signature_b64", None)
    # Use the same serialization as signing
    data = json.dumps(cert_unsigned, indent=2, ensure_ascii=False).encode("utf-8")
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return verify_signature_bytes(data, signature_b64, public_key)



def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
    
    

def verify_certificate(cert_path, public_key_path):
    cert = load_json(cert_path)
    public_key = load_public_key(public_key_path)
    import base64

    signature_b64 = cert.get("signature_b64", "")
    if not signature_b64:
        print("No signature found in certificate.")
        return
    signature = base64.b64decode(signature_b64)
    data = get_certificate_data(cert)
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Certificate is valid.")
    except Exception:
        print("Certificate is invalid or tampered.")


