import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def get_certificate_data(cert):
    # Remove signature_b64 and use indent=2, ensure_ascii=False for compatibility
    cert_data = dict(cert)
    cert_data.pop("signature_b64", None)
    return json.dumps(cert_data, indent=2, ensure_ascii=False).encode("utf-8")

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

def main():
    verify_certificate(r"output\certificate.signed.json", r"output\public_key.pem")

if __name__ == "__main__":
    main()
