import os
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import datetime

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
        return False
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

class CertificateVerificationError(Exception):
    """Custom exception for certificate verification errors"""
    pass

class CertificateValidator:
    def __init__(self, cert_path: str, public_key_path: str):
        self.cert_path = cert_path
        self.public_key_path = public_key_path
        self.verification_results = {}

    def verify(self) -> dict:
        """Complete certificate verification"""
        try:
            # Load certificate
            self.cert = load_json(self.cert_path)
            self.public_key = load_public_key(self.public_key_path)
            
            # Verify signature
            signature_valid = self._verify_signature()
            
            # Verify expiration
            is_expired = self._check_expiration()
            
            # Verify required fields
            missing_fields = self._check_required_fields()
            
            results = {
                "overall_valid": signature_valid and not is_expired and not missing_fields,
                "signature_valid": signature_valid,
                "is_expired": is_expired,
                "missing_fields": missing_fields,
                "certificate_id": self.cert["header"].get("certificate_id", "N/A"),
                "issued_on": self.cert["header"].get("issued_on", "N/A"),
                "valid_until": self.cert["header"].get("valid_until", "N/A"),
                "issuer": self.cert["header"].get("issuer_name", "N/A")
            }
            
            return results

        except Exception as e:
            raise CertificateVerificationError(f"Verification failed: {str(e)}")

    def _verify_signature(self) -> bool:
        """Verify digital signature"""
        try:
            signature_b64 = self.cert.get("signature_b64")
            if not signature_b64:
                return False
                
            data = get_certificate_data(self.cert)
            signature = base64.b64decode(signature_b64)
            
            self.public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def _check_expiration(self) -> bool:
        """Check if certificate is expired"""
        try:
            valid_until = datetime.datetime.strptime(
                self.cert["header"]["valid_until"],
                "%Y-%m-%dT%H:%M:%SZ"
            )
            return datetime.datetime.utcnow() > valid_until
        except (KeyError, ValueError):
            return True

    def _check_required_fields(self) -> list:
        """Check for required fields"""
        required = ["header", "device_information", "wipe_details", 
                   "cryptographic_integrity", "signature_b64"]
        return [field for field in required if field not in self.cert]

def print_verification_results(results: dict):
    """Print formatted verification results"""
    print("\n=== Certificate Verification Results ===")
    print(f"Overall Status: {'✓ VALID' if results['overall_valid'] else '❌ INVALID'}")
    print(f"Signature Status: {'✓ Valid' if results['signature_valid'] else '❌ Invalid'}")
    print(f"Expiration Status: {'❌ Expired' if results['is_expired'] else '✓ Valid'}")
    
    if results['missing_fields']:
        print(f"Missing Fields: {', '.join(results['missing_fields'])}")
    
    print("\nCertificate Details:")
    print(f"ID: {results['certificate_id']}")
    print(f"Issuer: {results['issuer']}")
    print(f"Issued On: {results['issued_on']}")
    print(f"Valid Until: {results['valid_until']}")
    print("=====================================\n")

def verify_certificate_enhanced(cert_path: str, public_key_path: str, show_results: bool = True) -> bool:
    """
    Enhanced certificate verification with detailed checks
    Returns True if certificate is valid, False otherwise
    """
    try:
        validator = CertificateValidator(cert_path, public_key_path)
        results = validator.verify()
        
        if show_results:
            print_verification_results(results)
            
        return results["overall_valid"]
        
    except CertificateVerificationError as e:
        print(f"Verification Error: {e}")
        return False

if __name__ == "__main__":
    verify_certificate_enhanced(r"certificate\json\certificate.signed.json", r"certificate\json\public_key.pem")