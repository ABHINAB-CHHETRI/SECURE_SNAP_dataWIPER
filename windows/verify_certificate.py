import json
from pdb import main
from wsgiref.validate import validator
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from crypto_utils import verify_certificate_enhanced


if __name__ == "__main__":
    verify_certificate_enhanced(
        r"certificate\json\certificate.signed.json",
        r"certificate\json\public_key.pem"
    )   
