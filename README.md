Secure Data Wiper - README
--------------------------

This program is a Python tool that securely wipes files or directories and creates a certificate to prove the action. It has a simple GUI built with Tkinter.

How it works:
1. When the program runs for the first time, it generates RSA keys (private and public) and saves them in a "Keys" folder.
   - Private key: used to sign certificates.
   - Public key: can be used later to verify signatures.

2. Wiping logic:
   - If the user selects a file, the program overwrites the file with zeros and then deletes it.
   - If the user selects a directory, the program deletes the entire directory and its contents.
   - This is a single pass overwrite. Recovery is not possible with normal methods.

3. Certificate:
   - After wiping, the program generates a PDF certificate in the "Certificates" folder.
   - The certificate includes:
     - The path that was wiped
     - Whether it was a file or directory
     - Date and time
     - Status of the wipe
     - A digital signature
   - The digital signature is generated using the private RSA key and is printed directly on the certificate.

4. GUI:
   - The GUI is built with Tkinter.
   - Buttons:
     - "Browse File" lets the user select a file.
     - "Browse Directory" lets the user select a directory.
     - "Wipe" starts the wiping process.
   - A log box shows messages about the process (for example: wiping started, wiping complete, certificate saved).

Project folders:
- Keys/ : stores the RSA keys
- Certificates/ : stores the PDF certificates
- wiper.py : the main program

Dependencies:
- cryptography (for RSA)
- reportlab (for generating PDF certificates)
- tkinter (built-in with Python)

Usage:
1. Run: python wiper.py
2. Select a file or directory.
3. Click Wipe.
4. A certificate is created automatically.

Important notes:
- Be careful: directories are deleted completely with no recovery.
- This is only a single pass zero overwrite. More advanced wipe standards (like multi-pass) can be added later.
- Certificates are signed for authenticity, but verification code is not yet included.
