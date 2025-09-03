import os
import uuid
import json
import datetime
from typing import Dict, Any, Tuple
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
import qrcode
from cryptography.hazmat.primitives import serialization
from crypto_utils import sign_json_bytes



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




def write_certificate_files(cert: Dict[str, Any], output_dirs, private_key, public_key) -> Tuple[str, str]:
    # output_dirs: dict with keys 'json' and 'pdf'
    json_dir = output_dirs["json"]
    pdf_dir = output_dirs["pdf"]
    os.makedirs(json_dir, exist_ok=True)
    os.makedirs(pdf_dir, exist_ok=True)

    # Generate signed certificate directly
    cert_bytes = json.dumps(cert, indent=2, ensure_ascii=False).encode("utf-8")
    signature_b64 = sign_json_bytes(cert_bytes, private_key)
    cert_signed = dict(cert)
    cert_signed["signature_b64"] = signature_b64
    cert_signed_path = os.path.join(json_dir, "certificate.signed.json")
    with open(cert_signed_path, "w", encoding="utf-8") as f:
        json.dump(cert_signed, f, indent=2, ensure_ascii=False)

    pubkey_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_path = os.path.join(json_dir, "public_key.pem")
    with open(pub_path, "wb") as f:
        f.write(pubkey_pem)

    pdf_path = os.path.join(pdf_dir, "certificate.pdf")
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
    qr_data = f"Certificate ID: {header.get('certificate_id')}\nVerify: https://www.secureerase,com/?id={header.get('certificate_id')}"
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
