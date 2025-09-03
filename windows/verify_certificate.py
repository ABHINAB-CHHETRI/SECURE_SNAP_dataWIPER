import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from crypto_utils import verify_certificate


def main():
    verify_certificate(r"output\json\certificate.signed.json", r"output\json\public_key.pem")

if __name__ == "__main__":
    main()
