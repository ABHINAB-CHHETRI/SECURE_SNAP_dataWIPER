#py -3.9 wiper_gui.py
import os
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64


# === Key Management ===
def generate_key_pair():
    key_dir = r"C:\Users\Abhinab\Desktop\DATA_wiper\Keys"
    os.makedirs(key_dir, exist_ok=True)
    private_key_file = os.path.join(key_dir, "private_key.pem")
    public_key_file = os.path.join(key_dir, "public_key.pem")

    if not os.path.exists(private_key_file):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(private_key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        public_key = private_key.public_key()
        with open(public_key_file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKey
            ))

    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key


# === PDF Certificate ===
def generate_pdf_certificate(file_path, path_type, output_text):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        cert_dir = r"C:\Users\Abhinab\Desktop\DATA_wiper\Certificates"
        os.makedirs(cert_dir, exist_ok=True)
        pdf_filename = os.path.join(cert_dir, f"wipe_certificate_{timestamp}.pdf")

        doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
        styles = getSampleStyleSheet()
        content = [
            Paragraph("WIPE OPERATION CERTIFICATE", styles['Title']),
            Spacer(1, 20),
            Paragraph(f"Path: {file_path}", styles['Normal']),
            Paragraph(f"Type: {path_type}", styles['Normal']),
            Paragraph(f"Date: {timestamp}", styles['Normal']),
            Paragraph("Status: Successfully wiped", styles['Normal']),
            Spacer(1, 20)
        ]

        private_key = generate_key_pair()
        data_to_sign = f"{file_path}|{path_type}|{timestamp}".encode()
        signature = private_key.sign(
            data_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode()
        content.append(Paragraph("Digital Signature:", styles['Heading2']))
        content.append(Paragraph(signature_b64, styles['Code']))

        doc.build(content)

        output_text.insert(tk.END, f"PDF certificate saved: {pdf_filename}\n\n")
    except Exception as e:
        output_text.insert(tk.END, f"Failed to generate PDF or signature: {e}\n\n")
        messagebox.showerror("Error", f"Failed to generate PDF or signature: {e}")


# === Wiping ===
def wipe_path(file_path, output_text):
    try:
        if not os.path.exists(file_path):
            output_text.insert(tk.END, f"Path does not exist: {file_path}\n\n")
            return

        path_type = "Directory" if os.path.isdir(file_path) else "File"

        if path_type == "File":
            with open(file_path, "r+b") as f:
                f.write(b'\x00' * os.path.getsize(file_path))
                f.flush()
            os.remove(file_path)
        else:
            shutil.rmtree(file_path)

        output_text.insert(tk.END, f"{path_type} wiped: {file_path}\n")
        certificate = f"\n{'='*40}\nWIPE CERTIFICATE\n{'='*40}\nPath: {file_path}\nType: {path_type}\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nStatus: Successfully wiped\n{'='*40}\n\n"
        output_text.insert(tk.END, certificate)
        generate_pdf_certificate(file_path, path_type, output_text)

    except PermissionError as e:
        output_text.insert(tk.END, f"Permission denied: {e}\n\n")
        messagebox.showerror("Error", f"Permission denied: {e}")
    except Exception as e:
        output_text.insert(tk.END, f"Wipe failed: {e}\n\n")
        messagebox.showerror("Error", f"Wipe failed: {e}")

    output_text.see(tk.END)


# === File/Directory Select ===
def select_file(path_label, output_text):
    path = filedialog.askopenfilename()
    if path:
        path_label.config(text=path)
        output_text.insert(tk.END, f"Selected File: {path}\n\n")
        output_text.see(tk.END)


def select_directory(path_label, output_text):
    path = filedialog.askdirectory()
    if path:
        path_label.config(text=path)
        output_text.insert(tk.END, f"Selected Directory: {path}\n\n")
        output_text.see(tk.END)


# === GUI ===
def create_gui():
    root = tk.Tk()
    root.title("Data Wiper")
    root.geometry("700x450")
    root.resizable(False, False)

    # Header
    tk.Label(root, text="Secure Data Wiper", font=("Arial", 14, "bold")).pack(pady=10)

    # Path Display
    path_label = tk.Label(root, text="No path selected", wraplength=650, font=("Arial", 10), relief="sunken", anchor="w")
    path_label.pack(pady=5, padx=10, fill="x")

    # Buttons
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Browse File", width=18,
              command=lambda: select_file(path_label, output_text)).grid(row=0, column=0, padx=10)

    tk.Button(button_frame, text="Browse Directory", width=18,
              command=lambda: select_directory(path_label, output_text)).grid(row=0, column=1, padx=10)

    tk.Button(button_frame, text="Wipe", width=18, bg="red", fg="white",
              command=lambda: wipe_path(path_label.cget("text"), output_text)).grid(row=0, column=2, padx=10)

    # Output Console
    output_text = scrolledtext.ScrolledText(root, height=15, wrap=tk.WORD, font=("Consolas", 9))
    output_text.pack(pady=10, padx=10, fill="both", expand=True)

    output_text.insert(tk.END,
        "Instructions:\n"
        "1. Click 'Browse File' or 'Browse Directory'.\n"
        "2. Click 'Wipe' to securely delete it.\n"
        "3. A signed PDF certificate will be saved in:\n"
        "   C:\\Users\\Abhinab\\Desktop\\DATA_wiper\\Certificates\n\n"
    )

    root.mainloop()


if __name__ == "__main__":
    create_gui()
