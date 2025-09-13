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
            print("Loading existing private key.")
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
        with open(private_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            print("Generated new private key.")
    if os.path.exists(public_path):
        with open(public_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            print("Loading existing public key.")
    else:
        public_key = private_key.public_key()
        with open(public_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            print("Generated new public key.")
    return private_key, public_key


def sign_json_bytes(data: bytes, private_key) -> str:
    print("Signing data...")
    print('Private Key Object:', private_key)
    print('Data to Sign:', data)
    print('\n========================\n')
    sig = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode("ascii")

def verify_signature_bytes(data: bytes, signature_b64: str, public_key) -> bool:
    try:
        print("Verifying signature...")
        print(signature_b64)
        sig = base64.b64decode(signature_b64)
        print("Decoded signature:", sig)
        public_key.verify(
            sig,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is valid.")
        return True
    except Exception:
        print("Signature is invalid.")
        return False


def verify_certificate_json(signed_json_path: str, public_key_path: str) -> bool:
    """
    Verifies signature embedded in signed JSON file produced by write_certificate_files.
    Returns True if valid.
    """
    with open(signed_json_path, "r", encoding="utf-8") as f:
        cert = json.load(f)
        # print("Loaded certificate JSON:", cert)
    signature_b64 = cert.get("signature_b64")
    # Create unsigned snapshot by removing signature_b64 before verification
    cert_unsigned = dict(cert)
    print("Before pop:", cert_unsigned.keys())
    cert_unsigned.pop("signature_b64", None)
    print("After pop:", cert_unsigned.keys())
    # Use the same serialization as signing
    data = json.dumps(cert_unsigned, indent=2, ensure_ascii=False).encode("utf-8")
    # print("Data for verification:", data)
    with open(public_key_path, "rb") as f:
        print("Opening public key file:", public_key_path)
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return verify_signature_bytes(data, signature_b64, public_key)



def load_public_key(path):
    with open(path, "rb") as f:
        print("Loading public key from:", path)
        return serialization.load_pem_public_key(f.read())
    
    

def verify_certificate(cert_path, public_key_path):
    cert = load_json(cert_path)
    print(type(cert),"=----------------------")
    public_key = load_public_key(public_key_path)
    import base64

    signature_b64 = cert.get("signature_b64", "")
    if not signature_b64:
        print("No signature found in certificate.")
        return False
    signature = base64.b64decode(signature_b64)
    for key,value in cert.items():
        print(f"{key}----> {value}",end='\n\n')
    data = get_certificate_data(cert)
    print(type(data))
    print("Data for verification:", data)
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Certificate is valid.")
        return True
    except Exception:
        print("Certificate is invalid or tampered.")
        return False

def create_cert_from_pdf(pdf_path: str) -> dict:
    from PyPDF2 import PdfReader
    import re
    import json
    cert = {
        "header": {
            "certificate_title": "",
            "issuer_name": "",
            "certificate_id": "",
            "issued_on": "",
            "valid_until": ""
        },
        "device_information": {
            "device_id": "",
            "device_model": "",
            "device_manufacturer": "",
            "operating_system": "",
            "os_version": "",
            "device_type": "",
            "storage_type": ""
        },
        "wipe_details": {
            "wipe_method": "",
            "wipe_level": "",
            "data_areas_wiped": {
                "main_storage": "",
                "hidden_storage_areas": "",
                "partition_information": "",
                "non_volatile_memory": ""
            },
            "data_wipe_duration_seconds": 0.0,
            "total_wiped_data_volume_bytes": 0,
            "wiped_file_count": 0,
            "wiped_files_snapshot": [],
            "verification_status": {
                "verified_files": [],
                "verification_method": "",
                "files_failed_verification": []
            },
            "directory_cleanup": {
                "empty_directories_removed": [],
                "directories_failed_removal": []
            }
        },
        "cryptographic_integrity": {
            "digital_signature": None,
            "public_key_certificate_path": "",
            "signature_algorithm": ""
        },
        "user_information": {
            "operator": "",
            "timestamp_utc_start": "",
            "timestamp_utc_end": ""
        },
        "wipe_process_details": {
            "application": "",
            "version": "",
            "platform": {
                "system": "",
                "release": "",
                "version": "",
                "machine": "",
                "node": ""
            }
        },
        "third_party_verification": {
            "verified_by": ""
        },
        "legal_disclaimer_and_terms": {
            "disclaimer": ""
        },
        "audit_trail": {
            "operator": "",
            "files_attempted": 0,
            "files_wiped": 0
        },
        "signature_and_authentication": {
            "issuer_organization": ""
        },
        "blockchain_id": {},
        "signature_b64": "",
        "public_key": {}
    }
    def parse_number(s):
        try:
            return int(s.replace(",", ""))
        except Exception:
            try:
                return float(s)
            except Exception:
                return None
    def parse_size(s):
        # return bytes
        s = s.strip()
        m = re.match(r"([\d\.,]+)\s*(B|KB|MB|GB|TB)?", s, re.IGNORECASE)
        if not m:
            return None
        num = float(m.group(1).replace(",", ""))
        unit = (m.group(2) or "B").upper()
        mult = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
        return int(num * mult.get(unit, 1))
    def find_field(text, patterns):
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return None
    def extract_list(text, header):
        # Try block under header (multiline bullet list)
        m = re.search(rf"{re.escape(header)}\s*[:\-]?\s*(?:\n|\r\n)([-\u2022\*\s\w\W]+?)(?:\n\s*\n|$)", text, re.IGNORECASE)
        if m:
            lines = [l.strip(" -\u2022*") for l in m.group(1).splitlines() if l.strip()]
            return lines
        # Try inline comma-separated
        m = re.search(rf"{re.escape(header)}\s*[:\-]\s*([^\n\r]+)", text, re.IGNORECASE)
        if m:
            return [i.strip() for i in re.split(r",\s*", m.group(1)) if i.strip()]
        return []
    try:
        reader = PdfReader(pdf_path)
        pages = []
        for p in reader.pages:
            t = p.extract_text()
            if t:
                pages.append(t)
        text = "\n\n".join(pages)
        # Map fields using heuristics / common labels
        cert["header"]["certificate_title"] = find_field(text, [r"Certificate\s*Title[:\-\s]+(.+)", r"Title[:\-\s]+(.+)"]) or cert["header"]["certificate_title"]
        cert["header"]["issuer_name"] = find_field(text, [r"Issuer\s*Name[:\-\s]+(.+)", r"Issuer[:\-\s]+(.+)"]) or cert["header"]["issuer_name"]
        cert["header"]["certificate_id"] = find_field(text, [r"Certificate\s*ID[:\-\s]+(.+)", r"ID[:\-\s]+([A-Za-z0-9\-\_]+)"]) or cert["header"]["certificate_id"]
        cert["header"]["issued_on"] = find_field(text, [r"Issued\s*On[:\-\s]+(.+)", r"Issued[:\-\s]+(.+)"]) or cert["header"]["issued_on"]
        cert["header"]["valid_until"] = find_field(text, [r"Valid\s*Until[:\-\s]+(.+)", r"Valid\s*Thru[:\-\s]+(.+)"]) or cert["header"]["valid_until"]
        # Device information
        cert["device_information"]["device_id"] = find_field(text, [r"Device\s*ID[:\-\s]+(.+)", r"device_id[:\-\s]+(.+)", r"Device\s*Identifier[:\-\s]+(.+)"]) or cert["device_information"]["device_id"]
        cert["device_information"]["device_model"] = find_field(text, [r"Device\s*Model[:\-\s]+(.+)", r"Model[:\-\s]+(.+)"]) or cert["device_information"]["device_model"]
        cert["device_information"]["device_manufacturer"] = find_field(text, [r"Manufacturer[:\-\s]+(.+)", r"Device\s*Manufacturer[:\-\s]+(.+)"]) or cert["device_information"]["device_manufacturer"]
        cert["device_information"]["operating_system"] = find_field(text, [r"Operating\s*System[:\-\s]+(.+)", r"OS[:\-\s]+(.+)"]) or cert["device_information"]["operating_system"]
        cert["device_information"]["os_version"] = find_field(text, [r"OS\s*Version[:\-\s]+(.+)", r"Operating\s*System\s*Version[:\-\s]+(.+)"]) or cert["device_information"]["os_version"]
        cert["device_information"]["device_type"] = find_field(text, [r"Device\s*Type[:\-\s]+(.+)", r"Type[:\-\s]+(.+)"]) or cert["device_information"]["device_type"]
        cert["device_information"]["storage_type"] = find_field(text, [r"Storage\s*Type[:\-\s]+(.+)", r"Storage[:\-\s]+(.+)"]) or cert["device_information"]["storage_type"]
        # Wipe details
        cert["wipe_details"]["wipe_method"] = find_field(text, [r"Wipe\s*Method[:\-\s]+(.+)", r"Method[:\-\s]+(.+)"]) or cert["wipe_details"]["wipe_method"]
        cert["wipe_details"]["wipe_level"] = find_field(text, [r"Wipe\s*Level[:\-\s]+(.+)", r"Level[:\-\s]+(.+)"]) or cert["wipe_details"]["wipe_level"]
        # Data areas wiped (try to extract subfields or list)
        data_areas = extract_list(text, "Data Areas Wiped") or []
        cert["wipe_details"]["data_areas_wiped"]["main_storage"] = find_field(text, [r"Main\s*Storage[:\-\s]+(.+)"]) or (data_areas[0] if len(data_areas) > 0 else cert["wipe_details"]["data_areas_wiped"]["main_storage"])
        cert["wipe_details"]["data_areas_wiped"]["hidden_storage_areas"] = find_field(text, [r"Hidden\s*Storage[:\-\s]+(.+)", r"Hidden\s*Storage\s*Areas[:\-\s]+(.+)"]) or (data_areas[1] if len(data_areas) > 1 else cert["wipe_details"]["data_areas_wiped"]["hidden_storage_areas"])
        cert["wipe_details"]["data_areas_wiped"]["partition_information"] = find_field(text, [r"Partition\s*Information[:\-\s]+(.+)"]) or (data_areas[2] if len(data_areas) > 2 else cert["wipe_details"]["data_areas_wiped"]["partition_information"])
        cert["wipe_details"]["data_areas_wiped"]["non_volatile_memory"] = find_field(text, [r"Non[-\s]?Volatile\s*Memory[:\-\s]+(.+)", r"NVM[:\-\s]+(.+)"]) or (data_areas[3] if len(data_areas) > 3 else cert["wipe_details"]["data_areas_wiped"]["non_volatile_memory"])
        # durations/sizes/counts
        dur = find_field(text, [r"(?:Wipe\s*)?Duration[:\-\s]+([0-9\.,]+)\s*seconds?", r"Duration\s*\(s\)[:\-\s]+([0-9\.,]+)"])
        if dur:
            cert["wipe_details"]["data_wipe_duration_seconds"] = float(dur.replace(",", ""))
        size_m = re.search(r"(?:Total\s*Wiped\s*Data\s*Volume|Total\s*Wiped)\s*[:\-\s]+([0-9\.,]+\s*(?:B|KB|MB|GB|TB)?)", text, re.IGNORECASE)
        if size_m:
            parsed = parse_size(size_m.group(1))
            if parsed is not None:
                cert["wipe_details"]["total_wiped_data_volume_bytes"] = parsed
        files_count = find_field(text, [r"Wiped\s*File\s*Count[:\-\s]+(\d+)", r"Files\s*Wiped[:\-\s]+(\d+)"])
        if files_count:
            cert["wipe_details"]["wiped_file_count"] = parse_number(files_count) or cert["wipe_details"]["wiped_file_count"]
        # lists of files etc.
        cert["wipe_details"]["wiped_files_snapshot"] = extract_list(text, "Wiped Files") or extract_list(text, "Files Wiped") or cert["wipe_details"]["wiped_files_snapshot"]
        # verification_status
        cert["wipe_details"]["verification_status"]["verified_files"] = extract_list(text, "Verified Files") or cert["wipe_details"]["verification_status"]["verified_files"]
        cert["wipe_details"]["verification_status"]["verification_method"] = find_field(text, [r"Verification\s*Method[:\-\s]+(.+)", r"Verification[:\-\s]+(.+)"]) or cert["wipe_details"]["verification_status"]["verification_method"]
        cert["wipe_details"]["verification_status"]["files_failed_verification"] = extract_list(text, "Files Failed Verification") or extract_list(text, "Failed Verification") or cert["wipe_details"]["verification_status"]["files_failed_verification"]
        # directory cleanup
        cert["wipe_details"]["directory_cleanup"]["empty_directories_removed"] = extract_list(text, "Empty Directories Removed") or cert["wipe_details"]["directory_cleanup"]["empty_directories_removed"]
        cert["wipe_details"]["directory_cleanup"]["directories_failed_removal"] = extract_list(text, "Directories Failed Removal") or cert["wipe_details"]["directory_cleanup"]["directories_failed_removal"]
        # cryptographic_integrity
        cert["cryptographic_integrity"]["digital_signature"] = find_field(text, [r"Digital\s*Signature[:\-\s]+(.+)", r"Signature[:\-\s]+(.+)"]) or cert["cryptographic_integrity"]["digital_signature"]
        cert["cryptographic_integrity"]["public_key_certificate_path"] = find_field(text, [r"Public\s*Key\s*Certificate\s*Path[:\-\s]+(.+)", r"Public\s*Key[:\-\s]+(.+)"]) or cert["cryptographic_integrity"]["public_key_certificate_path"]
        cert["cryptographic_integrity"]["signature_algorithm"] = find_field(text, [r"Signature\s*Algorithm[:\-\s]+(.+)", r"Algorithm[:\-\s]+(.+)"]) or cert["cryptographic_integrity"]["signature_algorithm"]
        # user_information
        cert["user_information"]["operator"] = find_field(text, [r"Operator[:\-\s]+(.+)", r"Performed\s*By[:\-\s]+(.+)"]) or cert["user_information"]["operator"]
        cert["user_information"]["timestamp_utc_start"] = find_field(text, [r"Start(?:ed)?\s*At[:\-\s]+(.+UTC.*|.+Z|.+)", r"Start\s*Time[:\-\s]+(.+)"]) or cert["user_information"]["timestamp_utc_start"]
        cert["user_information"]["timestamp_utc_end"] = find_field(text, [r"End(?:ed)?\s*At[:\-\s]+(.+UTC.*|.+Z|.+)", r"End\s*Time[:\-\s]+(.+)"]) or cert["user_information"]["timestamp_utc_end"]
        # wipe_process_details
        cert["wipe_process_details"]["application"] = find_field(text, [r"Application[:\-\s]+(.+)", r"Software[:\-\s]+(.+)"]) or cert["wipe_process_details"]["application"]
        cert["wipe_process_details"]["version"] = find_field(text, [r"Version[:\-\s]+(.+)", r"App\s*Version[:\-\s]+(.+)"]) or cert["wipe_process_details"]["version"]
        # platform details
        cert["wipe_process_details"]["platform"]["system"] = find_field(text, [r"Platform\s*System[:\-\s]+(.+)", r"System[:\-\s]+(.+)"]) or cert["wipe_process_details"]["platform"]["system"]
        cert["wipe_process_details"]["platform"]["release"] = find_field(text, [r"Platform\s*Release[:\-\s]+(.+)", r"Release[:\-\s]+(.+)"]) or cert["wipe_process_details"]["platform"]["release"]
        cert["wipe_process_details"]["platform"]["version"] = find_field(text, [r"Platform\s*Version[:\-\s]+(.+)", r"OS\s*Version[:\-\s]+(.+)"]) or cert["wipe_process_details"]["platform"]["version"]
        cert["wipe_process_details"]["platform"]["machine"] = find_field(text, [r"Machine[:\-\s]+(.+)", r"Architecture[:\-\s]+(.+)"]) or cert["wipe_process_details"]["platform"]["machine"]
        cert["wipe_process_details"]["platform"]["node"] = find_field(text, [r"Node[:\-\s]+(.+)", r"Host[:\-\s]+(.+)"]) or cert["wipe_process_details"]["platform"]["node"]
        # third party & legal
        cert["third_party_verification"]["verified_by"] = find_field(text, [r"Verified\s*By[:\-\s]+(.+)", r"Third[-\s]Party\s*Verification[:\-\s]+(.+)"]) or cert["third_party_verification"]["verified_by"]
        cert["legal_disclaimer_and_terms"]["disclaimer"] = find_field(text, [r"Disclaimer[:\-\s]+(.+)", r"Legal\s*Disclaimer[:\-\s]+(.+)"]) or cert["legal_disclaimer_and_terms"]["disclaimer"]
        # audit trail
        cert["audit_trail"]["operator"] = cert["user_information"].get("operator", cert["audit_trail"]["operator"])
        files_attempted = find_field(text, [r"Files\s*Attempted[:\-\s]+(\d+)", r"Attempted\s*Files[:\-\s]+(\d+)"])
        if files_attempted:
            cert["audit_trail"]["files_attempted"] = parse_number(files_attempted) or cert["audit_trail"]["files_attempted"]
        files_wiped = find_field(text, [r"Files\s*Wiped[:\-\s]+(\d+)", r"Wiped\s*Files[:\-\s]+(\d+)"])
        if files_wiped:
            cert["audit_trail"]["files_wiped"] = parse_number(files_wiped) or cert["audit_trail"]["files_wiped"]
        # signature & blockchain
        cert["signature_and_authentication"]["issuer_organization"] = find_field(text, [r"Issuer\s*Organization[:\-\s]+(.+)", r"Issuing\s*Organization[:\-\s]+(.+)"]) or cert["signature_and_authentication"]["issuer_organization"]
        # Try to extract a base64 signature block robustly (may be multi-line)
        sig_m = re.search(r"(?:Digital\s*Signature(?:\s*\(base64\))?|Digital\s*Signature|Signature\s*\(base64\))[:\-\s]*\n([\sA-Za-z0-9+/=]+)(?:\n\s*\n|$)", text, re.IGNORECASE)
        if sig_m:
            sig_text = sig_m.group(1)
            # remove whitespace/newlines inside the base64 block
            clean_sig = re.sub(r"\s+", "", sig_text)
            cert["signature_b64"] = clean_sig
        else:
            # fallback: any long base64-like chunk in the document
            long_b64 = re.search(r"([A-Za-z0-9+/=]{60,})", text)
            if long_b64:
                cert["signature_b64"] = long_b64.group(1).strip()
        # try blockchain id
        bc_id = find_field(text, [r"Blockchain\s*ID[:\-\s]+(.+)", r"Blockchain\s*Identifier[:\-\s]+(.+)"])
        if bc_id:
            cert["blockchain_id"] = {"id": bc_id}
        # try public key (PEM block anywhere in the text)
        pub_m = re.search(r"(-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----)", text)
        if pub_m:
            cert["public_key"] = {"pem": pub_m.group(1).strip()}
        else:
            # sometimes "Public Key :" prefix then PEM lines without the END marker on same capture - attempt looser capture
            pub_loose = re.search(r"Public\s*Key\s*[:\-]?\s*(-----BEGIN PUBLIC KEY-----[\s\S]+)", text)
            if pub_loose:
                pem_candidate = pub_loose.group(1)
                # try to clean up until END marker if present later
                end_m = re.search(r"-----END PUBLIC KEY-----", text[text.find(pem_candidate):])
                if end_m:
                    start_idx = text.find(pem_candidate)
                    end_idx = text.find("-----END PUBLIC KEY-----", start_idx) + len("-----END PUBLIC KEY-----")
                    cert["public_key"] = {"pem": text[start_idx:end_idx].strip()}
        # Print the filled certificate JSON for debugging
        print(json.dumps(cert, indent=2))
        return cert
    except Exception as e:
        print(f"Error reading or parsing PDF: {e}")
        return cert

def verify_certificate_from_pdf(pdf_path: str) -> bool:
    """
    Extract a certificate dictionary from a PDF and verify its embedded base64 signature
    using the embedded public key (PEM) or a referenced public key file. Returns True if valid.
    """
    cert = create_cert_from_pdf(pdf_path)
    if not cert:
        print("Failed to extract certificate from PDF.")
        return False
    print('*'*10)
    # try to read an existing signed JSON file if present (overrides/augments extracted cert)
    json_file = r'certificate\json\certificate.signed.json'
    json_content = None
    if os.path.exists(json_file):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                json_content = json.load(f)
            print("Loaded certificate JSON from", json_file)
        except Exception as e:
            print("Failed to load JSON file:", e)

    # prefer the JSON file if it was loaded, otherwise use the certificate extracted from PDF
    cert_to_verify = json_content if json_content else cert

    signature_b64 = cert_to_verify.get("signature_b64", "")
    if not signature_b64:
        print("No signature found in certificate.")
        return False

    # create unsigned snapshot (same serialization used for signing)
    cert_unsigned = dict(cert_to_verify)
    cert_unsigned.pop("signature_b64", None)
    data = json.dumps(cert_unsigned, indent=2, ensure_ascii=False).encode("utf-8")

    # determine public key: embedded PEM -> cert["public_key"]["pem"], else look for path in cryptographic_integrity
    public_key_obj = None
    pub_entry = cert_to_verify.get("public_key")
    if isinstance(pub_entry, dict) and pub_entry.get("pem"):
        pem_text = pub_entry["pem"]
        try:
            public_key_obj = serialization.load_pem_public_key(pem_text.encode("utf-8"), backend=default_backend())
            print("Using embedded PEM public key from PDF/json.")
        except Exception as e:
            print("Failed to load embedded PEM public key:", e)

    if public_key_obj is None:
        pub_path = cert_to_verify.get("cryptographic_integrity", {}).get("public_key_certificate_path", "")
        if pub_path and os.path.exists(pub_path):
            try:
                with open(pub_path, "rb") as f:
                    public_key_obj = serialization.load_pem_public_key(f.read(), backend=default_backend())
                print("Loaded public key from path:", pub_path)
            except Exception as e:
                print("Failed to load public key from path:", e)

    if public_key_obj is None:
        print("No valid public key available for verification.")
        return False

    # verify signature
    return verify_signature_bytes(data, signature_b64, public_key_obj)