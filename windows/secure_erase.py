# secure_erase.py
import os
import json
import uuid
import datetime
import base64
import hashlib
from typing import List, Dict, Any, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader

from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics import renderPDF
import qrcode
from io import BytesIO

# Key files (demo, store securely in production)
PRIVATE_KEY_FILE = "cert_private_key.pem"
PUBLIC_KEY_FILE = "cert_public_key.pem"

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

def build_certificate(
    device_info: Dict[str, Any],
    wipe_details: Dict[str, Any],
    crypto_info: Dict[str, Any],
    user_info: Dict[str, Any],
    process_details: Dict[str, Any],
    third_party: Dict[str, Any],
    disclaimer_terms: Dict[str, Any],
    audit_trail: Dict[str, Any],
    signature_auth: Dict[str, Any],
    blockchain_id: Dict[str, Any]
) -> Dict[str, Any]:
    header = {
        "certificate_title": "Certificate of Secure Data Wipe",
        "issuer_name": "SecureWipe Certification Authority (Demo)",
        "certificate_id": f"WPS-{uuid.uuid4().hex[:20].upper()}",
        "issued_on": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valid_until": (datetime.datetime.utcnow() + datetime.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    cert = {
        "header": header,
        "device_information": device_info,
        "wipe_details": wipe_details,
        "cryptographic_integrity": crypto_info,
        "user_information": user_info,
        "wipe_process_details": process_details,
        "third_party_verification": third_party,
        "legal_disclaimer_and_terms": disclaimer_terms,
        "audit_trail": audit_trail,
        "signature_and_authentication": signature_auth,
        "blockchain_id": blockchain_id
    }
    return cert

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

def write_certificate_files(cert: Dict[str, Any], output_dir: str, private_key, public_key) -> Tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    cert_json_path = os.path.join(output_dir, "certificate.json")
    # Always use the same serialization for signing and verification
    cert_bytes = json.dumps(cert, indent=2, ensure_ascii=False).encode("utf-8")
    with open(cert_json_path, "wb") as f:
        f.write(cert_bytes)

    # sign the JSON
    signature_b64 = sign_json_bytes(cert_bytes, private_key)

    # attach signature into the certificate structure (but keep a detached signature file too)
    cert_signed = dict(cert)
    cert_signed["signature_b64"] = signature_b64
    cert_signed_path = os.path.join(output_dir, "certificate.signed.json")
    with open(cert_signed_path, "w", encoding="utf-8") as f:
        json.dump(cert_signed, f, indent=2, ensure_ascii=False)

    sig_path = os.path.join(output_dir, "certificate.signature.b64")
    with open(sig_path, "w") as f:
        f.write(signature_b64)

    # Store the exact signed bytes for debugging
    debug_bytes_path = os.path.join(output_dir, "certificate.signed_bytes.json")
    with open(debug_bytes_path, "wb") as f:
        f.write(cert_bytes)

    # write public key for verification
    pubkey_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_path = os.path.join(output_dir, "public_key.pem")
    with open(pub_path, "wb") as f:
        f.write(pubkey_pem)

    # generate human-readable PDF
    pdf_path = os.path.join(output_dir, "certificate.pdf")
    # Generate PDF certificate
    generate_pdf_from_cert(cert_signed, pdf_path, pubkey_pem, signature_b64)

    return cert_signed_path, pdf_path


def generate_pdf_from_cert(cert: Dict[str, Any], pdf_path: str, public_key_pem: bytes, signature_b64: str):
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    y = height - 50

    # ===== Watermark logo (center faded) =====
    logo_path = os.path.join(os.path.dirname(pdf_path), "logo.webp")
    if os.path.exists(logo_path):
        try:
            logo = ImageReader(logo_path)
            c.saveState()
            c.translate(width/2, height/2)
            c.rotate(30)
            c.setFillAlpha(0.06)
            c.drawImage(logo, -200, -200, width=400, height=400, mask='auto')
            c.restoreState()
        except Exception:
            pass

    # ===== Premium Heading Box =====
    heading_height = 120
    heading_left = 40
    heading_width = width - 80
    heading_top = height - heading_height - 30

    # Gradient rectangle background
    def draw_gradient(c, x, y, w, h, color1, color2):
        steps = 60
        for i in range(steps):
            c.setFillColor(colors.linearlyInterpolatedColor(color1, color2, 0, steps, i))
            c.rect(x, y + (h * i / steps), w, h / steps, stroke=0, fill=1)

    c.saveState()
    draw_gradient(c, heading_left, heading_top, heading_width, heading_height, 
                  colors.HexColor('#0d47a1'), colors.HexColor('#1976d2'))
    c.setStrokeColor(colors.gold)
    c.setLineWidth(4)
    c.roundRect(heading_left, heading_top, heading_width, heading_height, 20, fill=0, stroke=1)
    c.restoreState()

    # ===== Header content =====
    header = cert.get("header", {})
    c.setFont("Helvetica-Bold", 24)
    c.setFillColor(colors.white)
    c.drawCentredString(width/2, heading_top + heading_height - 35, header.get("certificate_title", "Certificate"))

    c.setFont("Helvetica", 12)
    c.drawCentredString(width/2, heading_top + heading_height - 60, f"Issued by: {header.get('issuer_name')}")
    c.drawCentredString(width/2, heading_top + heading_height - 80, f"Certificate ID: {header.get('certificate_id')}")
    c.drawCentredString(width/2, heading_top + heading_height - 95, f"Issued on: {header.get('issued_on')}")
    c.drawCentredString(width/2, heading_top + heading_height - 110, f"Valid Until: {header.get('valid_until')}")

    # Logo on left
    if os.path.exists(logo_path):
        try:
            logo = ImageReader(logo_path)
            c.drawImage(logo, heading_left + 10, heading_top + 20, width=80, height=80, mask='auto')
        except Exception:
            pass

    # QR code on right
    qr_data = f"Certificate ID: {header.get('certificate_id')}\nVerify: https://secureerase/?id={header.get('certificate_id')}"
    try:
        qr = qrcode.QRCode(box_size=2, border=1)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        qr_img = ImageReader(buf)
        c.drawImage(qr_img, heading_left + heading_width - 70, heading_top + 30, width=60, height=60)
    except Exception:
        pass

    # ===== Content sections =====
    y = heading_top - 30

    def write_line(text, indent=0, size=9, bold=False):
        nonlocal y
        if y < 60:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.setFillColor(colors.black)
        c.drawString(60 + indent, y, text)
        y -= size + 4

    def dump_section(title, obj):
        nonlocal y
        write_line(title, bold=True, size=11)
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, dict):
                    write_line(f"{k}:", indent=10, bold=True)
                    for k2, v2 in v.items():
                        write_line(f"  {k2}: {v2}", indent=20)
                elif isinstance(v, list):
                    write_line(f"{k}: {', '.join(str(x) for x in v)}", indent=10)
                else:
                    write_line(f"{k}: {v}", indent=10)
        else:
            write_line(str(obj), indent=10)
        y -= 8

    dump_section("Device Information", cert.get("device_information", {}))
    dump_section("Wipe Details", cert.get("wipe_details", {}))
    dump_section("Cryptographic Integrity", cert.get("cryptographic_integrity", {}))
    dump_section("User / Requestor Information", cert.get("user_information", {}))
    dump_section("Wipe Process Details", cert.get("wipe_process_details", {}))
    dump_section("Audit Trail", cert.get("audit_trail", {}))

    # ===== Signature Block =====
    y -= 10
    write_line("Digital Signature (Base64):", bold=True)
    sig = signature_b64
    for i in range(0, len(sig), 100):
        write_line(sig[i:i+100], indent=10, size=7)

    y -= 8
    write_line("Public Key (PEM - first lines):", bold=True)
    for line in public_key_pem.decode("utf-8").splitlines()[:6]:
        write_line(line, indent=10, size=7)

    # ===== Footer =====
    y = 40
    c.setFont("Helvetica-Oblique", 8)
    c.setFillColor(colors.grey)
    c.drawCentredString(width/2, y, "This certificate is generated digitally and verifiable using the attached signature & public key.")

    c.save()

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

# High level function to run wipe and produce certificate (called by GUI)
def wipe_folder_and_certify(folder_path: str, operator_id: str, passes: int = 3, output_dir: str = "output"):
    """
    WARNING: Destructive. Overwrites and deletes files in folder_path.
    Returns paths to signed JSON and PDF certificate.
    """
    private_key, public_key = ensure_keypair()
    files, total_size, hidden_files = collect_files(folder_path)
    start_time = datetime.datetime.utcnow()
    # compute hashes BEFORE overwriting
    file_hashes = []
    for fpath in files:
        try:
            h = sha256_file(fpath)
            file_hashes.append({"path": fpath, "sha256": h, "size": os.path.getsize(fpath)})
        except Exception as e:
            file_hashes.append({"path": fpath, "sha256": None, "size": None, "error": str(e)})

    # perform secure wipe
    wiped_count = 0
    for fpath in files:
        try:
            secure_wipe_file(fpath, passes=passes)
            wiped_count += 1
        except Exception as e:
            # continue on error, record in audit
            pass

    # remove empty dirs
    for root, dirs, _ in os.walk(folder_path, topdown=False):
        for d in dirs:
            dir_path = os.path.join(root, d)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
            except Exception:
                pass

    end_time = datetime.datetime.utcnow()
    duration = (end_time - start_time).total_seconds()

    # Build certificate data
    device_info = {
        "device_id": os.uname().nodename if hasattr(os, "uname") else os.getenv("COMPUTERNAME", "unknown"),
        "device_model": os.uname().machine if hasattr(os, "uname") else "unknown",
        "device_manufacturer": os.uname().sysname if hasattr(os, "uname") else "unknown",
        "operating_system": os.name,
        "os_version": repr(os.sys.platform),
        "device_type": "PC",
        "storage_type": "SSD/HDD (folder-level wipe)"
    }

    wipe_details = {
        "wipe_method": f"NIST SP 800-88: {passes}-pass overwrite (file-level).",
        "wipe_level": "Folder/Files Full Wipe",
        "data_areas_wiped": {
            "main_storage": f"{round(total_size/1e9, 4)}GB wiped",
            "hidden_storage_areas": f"{hidden_files}",
            "partition_information": "N/A (folder-level)",
            "non_volatile_memory": "N/A"
        },
        "data_wipe_duration_seconds": duration,
        "total_wiped_data_volume_bytes": total_size,
        "wiped_file_count": wiped_count,
        "wiped_files_snapshot": file_hashes
    }

    crypto_info = {
        "digital_signature": None,  # will be filled after signing
        "public_key_certificate_path": os.path.abspath(PUBLIC_KEY_FILE),
        "signature_algorithm": "RSA-3072|SHA256",
    }

    user_info = {
        "operator": operator_id,
        "timestamp_utc_start": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp_utc_end": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    process_details = {
        "application": "SecureErase Demo",
        "version": "v_demo_1.0",
        "platform": platform_info_simple()
    }

    third_party = {"verified_by": "N/A"}
    disclaimer_terms = {"disclaimer": "Demo software. Use responsibly. No warranty."}
    audit_trail = {"operator": operator_id, "files_attempted": len(files), "files_wiped": wiped_count}
    signature_auth = {"issuer_organization": "SecureWipe Certification Authority (Demo)"}
    blockchain_id = {}

    cert = build_certificate(device_info, wipe_details, crypto_info, user_info, process_details,
                             third_party, disclaimer_terms, audit_trail, signature_auth, blockchain_id)

    # write & sign
    output_dir = os.path.abspath(output_dir)
    signed_json_path, pdf_path = write_certificate_files(cert, output_dir, private_key, public_key)
    return signed_json_path, pdf_path

def platform_info_simple():
    try:
        import platform as _p
        return {
            "system": _p.system(),
            "release": _p.release(),
            "version": _p.version(),
            "machine": _p.machine(),
            "node": _p.node(),
        }
    except Exception:
        return {}
