import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from crypto_utils import verify_certificate,verify_certificate_from_pdf


def main():
    flag=verify_certificate(r"certificate\json\certificate.signed.json", r"certificate\json\public_key.pem")
    # verify_certificate(r"certificate\json\certificate.signed.json", r"cert_public_key.pem")
    print( flag)
if __name__ == "__main__":
    # main()
    # print("\n\n")
    pdf_path = r"certificate\pdf\certificate.pdf"
    pdf_dict = verify_certificate_from_pdf(pdf_path)
    print( pdf_dict,type(pdf_dict),sep='\n========================\n')