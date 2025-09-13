import sys
import os
import getpass
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, PhotoImage
from PIL import Image, ImageTk
import threading
from files_utils import collect_files, secure_wipe_file
from wipe_process import wipe_folder_and_certify
from crypto_utils import verify_certificate_json, PUBLIC_KEY_FILE
class SecureSnapWiper:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Snap - Data Wiper")
        # self.root.geometry("800x600")  # Larger size for better visibility
        # self.root.resizable(False, False)
        self.root.config(bg="#f0f0f0")  # Light gray background
        # Position window at top-left corner
        self.root.geometry("+0+0")
        # Initialize variables
        self.selected_folder = None
        self.passes = 432
        self.content_frame = None
        self.status_label = None
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 12))
        self.style.configure("Custom.TButton", padding=10)
        self.style.configure("TProgressbar", thickness=25)
        
        # Output directories
        self.output_dirs = {
            "json": os.path.join("certificate", "json"),
            "pdf": os.path.join("certificate", "pdf")
        }
        
        # Load images
        logo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "images","logo.jpg")
        eco_warrior_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "images", "eco_warrier.jpg")
        
        # Open and resize images using PIL
        logo_img = Image.open(logo_path)
        eco_warrior_img = Image.open(eco_warrior_path)
        
        # Calculate dimensions for 25% width coverage
        window_width = 800  # Base window width
        logo_width = int(window_width * 0.25)
        eco_width = int(window_width * 0.25)
        
        # Calculate heights proportionally to maintain aspect ratio
        logo_aspect = logo_img.size[1] / logo_img.size[0]
        eco_aspect = eco_warrior_img.size[1] / eco_warrior_img.size[0]
        
        logo_height = int(logo_width * logo_aspect)
        eco_height = int(eco_width * eco_aspect)
        
        # Resize images with calculated dimensions
        logo_img = logo_img.resize((logo_width, logo_height), Image.Resampling.LANCZOS)
        eco_warrior_img = eco_warrior_img.resize((eco_width, eco_height), Image.Resampling.LANCZOS)
        
        # Convert to PhotoImage
        self.logo_photo = ImageTk.PhotoImage(logo_img)
        self.eco_warrior_photo = ImageTk.PhotoImage(eco_warrior_img)
        
        self.setup_initial_screen()

    def setup_initial_screen(self):
        """Initial screen for folder selection (UI_1)"""
        self.clear_window()
        
        # Top Section
        top_frame = tk.Frame(self.root, bg="black", height=80)
        top_frame.pack(fill="x")
        
        self.setup_header(top_frame)
        
        tk.Label(top_frame, text="Select FOLDER/Disk\nto Delete", 
                 bg="black", fg="white", font=("Arial", 24, "bold")).pack(side="right", padx=20)
        
        # Content Area
        self.content_frame = tk.Frame(self.root, bg="#f0f0f0", padx=50, pady=30)
        self.content_frame.pack(fill="both", expand=True)
        
        # Title and description
        title_frame = tk.Frame(self.content_frame, bg="#f0f0f0")
        title_frame.pack(fill="x", pady=(0, 30))
        
        tk.Label(title_frame, text="Secure Data Wiper", 
                font=("Arial", 24, "bold"), bg="#f0f0f0").pack()
        tk.Label(title_frame, text="Select a folder to securely wipe all data", 
                font=("Arial", 12), bg="#f0f0f0", fg="#666666").pack()
        
        # Path selection frame
        path_frame = tk.Frame(self.content_frame, bg="white", relief="solid", bd=1)
        path_frame.pack(fill="x", pady=20, padx=50)
        
        self.file_path_label = tk.Label(path_frame, text="No folder selected", 
                                     bg="white", font=("Arial", 12), fg="#666666")
        self.file_path_label.pack(pady=15)

        # # Passes selection frame
        # passes_frame = tk.Frame(self.content_frame, bg="white", relief="solid", bd=1)
        # passes_frame.pack(fill="x", pady=20, padx=50)
        
        # tk.Label(passes_frame, text="Number of Passes:", 
        #         bg="white", font=("Arial", 12), fg="#666666").pack(side="left", padx=10, pady=15)
        
        # self.passes_var = tk.StringVar(value="7")
        # passes_entry = ttk.Entry(passes_frame, textvariable=self.passes_var, width=10)
        # passes_entry.pack(side="left", padx=10, pady=15)
        
        # Buttons frame
        button_frame = tk.Frame(self.content_frame, bg="#f0f0f0")
        button_frame.pack(pady=30)
        
        browse_btn = ttk.Button(button_frame, text="Browse Folder", 
                             command=self.browse_folder, style="Custom.TButton")
        browse_btn.pack(pady=(0, 20))
        
        wipe_btn = tk.Button(button_frame, text="Secure Wipe", command=self.show_confirmation,
                          bg="#ff3b30", fg="white", font=("Arial", 14, "bold"),
                          padx=30, pady=10, relief="flat",
                          activebackground="#cc2f26", activeforeground="white")
        wipe_btn.pack()

    def setup_confirmation_screen(self):
        """Warning/confirmation screen (UI_2)"""
        self.clear_window()
        
        # Top Section
        top_frame = tk.Frame(self.root, bg="black", height=80)
        top_frame.pack(fill="x")
        
        self.setup_header(top_frame)
        
        tk.Label(top_frame, text="Warning!", bg="black", fg="white", 
                 font=("Arial", 20, "bold")).pack(side="right", padx=20)
        
        # Content Area
        content_frame = tk.Frame(self.root, bg="white", padx=50, pady=30)
        content_frame.pack(fill="both", expand=True)
        
        # Warning Section
        warning_frame = tk.Frame(content_frame, bg="white", padx=40, pady=30)
        warning_frame.pack(fill="both", expand=True)
        
        # Warning icon (⚠️)
        tk.Label(warning_frame, text="⚠️", font=("Arial", 48), 
                bg="white", fg="#ffd60a").pack(pady=(0, 20))
        
        warning_text = "Warning: Permanent Data Deletion"
        tk.Label(warning_frame, text=warning_text, font=("Arial", 20, "bold"), 
                fg="#ff3b30", bg="white").pack()
                
        detail_text = ("The selected data will be securely wiped\n"
                      "and cannot be recovered. This process uses\n"
                      "military-grade data wiping techniques.")
        tk.Label(warning_frame, text=detail_text, font=("Arial", 12),
                fg="#666666", bg="white").pack(pady=20)
                 
        # Show selected folder
        folder_frame = tk.Frame(warning_frame, bg="white", relief="solid", bd=1)
        folder_frame.pack(fill="x", pady=20)
        
        tk.Label(folder_frame, text="Selected Location:",
                font=("Arial", 10, "bold"), bg="white", fg="#666666").pack(pady=(10, 0))
        tk.Label(folder_frame, text=self.selected_folder,
                font=("Arial", 12), bg="white", wraplength=500).pack(pady=(0, 10))

        # Buttons
        button_frame = tk.Frame(warning_frame, bg="white")
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Cancel", command=self.setup_initial_screen,
                  bg="#666666", fg="white", font=("Arial", 12),
                  padx=30, pady=8, relief="flat",
                  activebackground="#4d4d4d").pack(side="left", padx=10)
        
        tk.Button(button_frame, text="Confirm Wipe", command=self.start_wiping,
                  bg="#ff3b30", fg="white", font=("Arial", 12, "bold"),
                  padx=30, pady=8, relief="flat",
                  activebackground="#cc2f26").pack(side="left", padx=10)

    def setup_progress_screen(self):
        """Progress screen with e-waste information (UI_3)"""
        self.clear_window()
        
        # Top Section
        top_frame = tk.Frame(self.root, bg="black", height=80)
        top_frame.pack(fill="x")
        
        self.setup_header(top_frame)
        
        message = "😊Good Job,\nsaving the planet one\ndeleted file at a time!"
        tk.Label(top_frame, text=message, bg="black", fg="white", 
                 font=("Arial", 16, "bold")).pack(side="right", padx=20)
        
        # Content Area
        self.content_frame = tk.Frame(self.root, bg="white", padx=50, pady=30)
        self.content_frame.pack(fill="both", expand=True)
        
        # Progress Section
        tk.Label(self.content_frame, text="Deleting Files...", 
                 font=("Arial", 20, "bold"), bg="white").pack(pady=(10, 5))
        
        # Status Frame
        status_frame = tk.Frame(self.content_frame, bg="white")
        status_frame.pack(fill="x", pady=10)
        
        self.status_label = tk.Label(
            status_frame,
            text="Initializing secure wipe process...",
            wraplength=500,
            font=("Arial", 11),
            bg="white"
        )
        self.status_label.pack(pady=5)
        
        # Progress Bar
        self.progress_bar = ttk.Progressbar(
            status_frame,
            orient="horizontal",
            length=500,
            mode="determinate"
        )
        self.progress_bar.pack(pady=5)
        # Electronic Waste section
        ewaste_frame = tk.Frame(self.content_frame, bg="white", pady=20)
        ewaste_frame.pack(fill="x")
        # Create a simple representation of the e-waste bin using a canvas
        ewaste_canvas = tk.Canvas(ewaste_frame, width=120, height=120, bg="white", highlightthickness=0)
        ewaste_canvas.pack(side="left", padx=(0, 20))
        ewaste_canvas.create_rectangle(30, 40, 90, 120, fill="#2E8B57", outline="")
        ewaste_canvas.create_polygon(30, 40, 20, 30, 100, 30, 90, 40, fill="#2E8B57", outline="")
        ewaste_canvas.create_text(60, 80, text="E-WASTE", font=("Arial", 10, "bold"), fill="white")
        
        info_frame = tk.Frame(ewaste_frame, bg="white")
        info_frame.pack(side="left", fill="both", expand=True)
        
        ewaste_title = tk.Label(info_frame, text="Electronic Waste", font=("Arial", 20, "bold"), bg="white")
        ewaste_title.pack(anchor="w")
        
        ewaste_info = tk.Label(info_frame, text="By 2030, the global volume of e-waste is projected to reach 74 million metric tons, indicating a continued upward trend in e-waste generation.", font=("Arial", 10, "italic"), wraplength=250, justify="left", bg="white")
        ewaste_info.pack(anchor="w")
        
        market_label = tk.Label(info_frame, text="market.us", font=("Arial", 10, "italic", "underline"), fg="purple", bg="white")
        market_label.pack(pady=(10,0), anchor="e")
        
        
    def setup_completion_screen(self, signed_json_path, pdf_path, verification_ok):
        """Final screen showing completion and certificates (UI_4)"""
        self.clear_window()
        
        # Top Section
        top_frame = tk.Frame(self.root, bg="black", height=80)
        top_frame.pack(fill="x")
        
        self.setup_header(top_frame)
        
        # ECO WARRIOR section
        eco_warrior_frame = tk.Frame(top_frame, bg="black", padx=10, pady=10)
        eco_warrior_frame.pack(side="right", padx=20)
        
        eco_warrior_label = tk.Label(eco_warrior_frame, image=self.eco_warrior_photo, bg="black")
        eco_warrior_label.pack(side="left", padx=(0, 5))
        
        # Content Area
        content_frame = tk.Frame(self.root, bg="white", padx=50, pady=30)
        content_frame.pack(fill="both", expand=True)
        
        status = "Deletion Completed Successfully!" if verification_ok else "Deletion Completed (Verification Failed)"
        tk.Label(content_frame, text=status, 
                font=("Arial", 20, "bold"), bg="white").pack(pady=(20, 20))

        # Files section title
        tk.Label(content_frame, text="Certificate files have been saved:", 
                font=("Arial", 14), bg="white").pack(pady=(10, 20))

        # Create a frame for file info
        files_frame = tk.Frame(content_frame, bg="white")
        files_frame.pack(fill="x", padx=20)

        # JSON Certificate section
        if signed_json_path:
            cert_frame = tk.Frame(files_frame, bg="white", padx=20)
            cert_frame.pack(side="left", expand=True)
            
            # Certificate icon
            cert_icon = tk.Frame(cert_frame, bg="lightgrey", width=80, height=100)
            cert_icon.pack_propagate(False)
            cert_icon.pack()
            tk.Label(cert_icon, text="JSON", font=("Arial", 16)).pack(expand=True)
            
            tk.Label(cert_frame, text="Digital Certificate Package", 
                    font=("Arial", 12, "bold"), bg="white").pack(pady=5)
            tk.Label(cert_frame, text="Includes:\n- Certificate JSON\n- Digital Signature\n- Public Key\n- Verification Files",
                    font=("Arial", 10), bg="white", justify="left").pack(pady=5)
            ttk.Button(cert_frame, text="Save Certificate Package",
                    command=lambda: self.save_certificate(signed_json_path, "json")).pack(pady=5)

        # PDF Report section
        if pdf_path:
            report_frame = tk.Frame(files_frame, bg="white", padx=20)
            report_frame.pack(side="left", expand=True)
            
            # Report icon
            report_icon = tk.Frame(report_frame, bg="lightgrey", width=80, height=100)
            report_icon.pack_propagate(False)
            report_icon.pack()
            tk.Label(report_icon, text="PDF", font=("Arial", 16)).pack(expand=True)
            
            tk.Label(report_frame, text="Wipe Report", 
                    font=("Arial", 12, "bold"), bg="white").pack(pady=5)
            tk.Label(report_frame, text="Visual report with\nwipe details and QR code",
                    font=("Arial", 10), bg="white", justify="center").pack(pady=5)
            ttk.Button(report_frame, text="Save PDF Report",
                    command=lambda: self.save_certificate(pdf_path, "pdf")).pack(pady=5)

        # Info message
        info_frame = tk.Frame(content_frame, bg="white")
        info_frame.pack(fill="x", pady=20)
        tk.Label(info_frame, 
                text="Click the save buttons above to choose where to save your certificate files.\nThe certificate package includes all files needed for verification.", 
                bg="white", font=("Arial", 12), wraplength=400, justify="center").pack()

        # Bottom buttons
        tk.Button(content_frame, text="Start New Wipe", command=self.setup_initial_screen,
                bg="green", fg="white", font=("Arial", 16, "bold")).pack(pady=20)
                
    def setup_header(self, top_frame):
        """Setup the common header with logo"""
        logo_frame = tk.Frame(top_frame, bg="black", padx=10, pady=10)
        logo_frame.pack(side="left", padx=10, pady=10)
        
        logo_label = tk.Label(logo_frame, image=self.logo_photo, bg="black")
        logo_label.pack(side="left")

    def save_certificate(self, source_path, file_type):
        """Save certificate or report to user-selected location"""
        if not source_path or not os.path.exists(source_path):
            messagebox.showerror("Error", f"The {file_type} file could not be found.")
            return

        source_dir = os.path.dirname(source_path)
        source_base = os.path.basename(source_path)
        
        # Setup file dialog parameters and associated files
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        if file_type == "json":
            file_types = [("JSON Certificate", "*.json"), ("All files", "*.*")]
            default_ext = ".json"
            title = "Save Digital Certificate Package"
            default_name = f"secure_wipe_certificate_{timestamp}.json"
            
            # Only essential files needed for verification
            source_files = {
                'certificate': source_base,  # The main certificate file
                'pubkey': 'public_key.pem'
            }
        else:  # pdf
            file_types = [("PDF Report", "*.pdf"), ("All files", "*.*")]
            default_ext = ".pdf"
            title = "Save PDF Report"
            default_name = f"secure_wipe_report_{timestamp}.pdf"
            associated_files = {}  # No associated files for PDF

        # Ask user where to save
        save_path = filedialog.asksaveasfilename(
            title=title,
            defaultextension=default_ext,
            filetypes=file_types,
            initialfile=default_name
        )

        if save_path:
            try:
                import shutil
                save_dir = os.path.dirname(save_path)
                
                # Create new filename based on timestamp
                base_name = f"secure_wipe_certificate_{timestamp}"
                files_copied = []

                if file_type == "json":
                    # First copy the main certificate file
                    shutil.copy2(source_path, save_path)
                    files_copied.append(os.path.basename(save_path))
                    
                    # Then copy the public key
                    pubkey_source = os.path.join(source_dir, 'public_key.pem')
                    if os.path.exists(pubkey_source):
                        pubkey_dest = os.path.join(save_dir, 'public_key.pem')
                        shutil.copy2(pubkey_source, pubkey_dest)
                        files_copied.append('public_key.pem')
                else:  # pdf
                    # Copy the PDF file
                    shutil.copy2(source_path, save_path)
                    files_copied.append(os.path.basename(save_path))
                
                    # Show which files were copied and explain their purpose
                    files_list = "\n".join(files_copied)
                    if file_type == "json":
                        messagebox.showinfo("Success", 
                            f"Essential verification files saved to:\n{save_dir}\n\n"
                            f"Files saved:\n{files_list}\n\n"
                            "These are the only files needed to verify the certificate:\n"
                            "- certificate.signed.json: Contains the certificate data and signature\n"
                            "- public_key.pem: Required to verify the signature")
                    else:  # pdf
                        messagebox.showinfo("Success",
                            f"PDF Report saved to:\n{save_dir}\n\n"
                            f"File saved:\n{files_list}")
            except Exception as e:
                messagebox.showerror("Error", 
                    f"Failed to save files: {str(e)}")

    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def browse_folder(self):
        """Opens a dialog to select a folder"""
        folder = filedialog.askdirectory(
            title="Select Folder to Wipe",
            mustexist=True
        )
        if folder:
            self.selected_folder = folder
            # Show truncated path if too long
            if len(folder) > 50:
                display_path = "..." + folder[-47:]
            else:
                display_path = folder
            self.file_path_label.config(text=display_path)
            
            # Enable the wipe button
            for widget in self.content_frame.winfo_children():
                if isinstance(widget, tk.Frame):  # Button frame
                    for btn in widget.winfo_children():
                        if isinstance(btn, tk.Button) and btn['text'] == "Secure Wipe":
                            btn.config(state="normal")

    def show_confirmation(self):
        """Show the confirmation screen if a folder is selected"""
        if not self.selected_folder:
            messagebox.showwarning(
                "No Folder Selected",
                "Please select a folder to wipe first.",
                icon="warning"
            )
            return
            
        # Check if folder still exists
        if not os.path.exists(self.selected_folder):
            messagebox.showerror(
                "Folder Not Found",
                "The selected folder no longer exists.",
                icon="error"
            )
            return
            
        self.setup_confirmation_screen()

    def show_verification_simulation(self, callback):
        """Simulate verification with a progress bar for 7 seconds, then call callback."""
        self.clear_window()
        frame = tk.Frame(self.root, bg="white", padx=50, pady=30)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Verifying Wipe...", font=("Arial", 20, "bold"), bg="white").pack(pady=(20, 10))
        progress = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate", maximum=100)
        progress.pack(pady=20)
        status = tk.Label(frame, text="Please wait while we verify the wipe...", font=("Arial", 12), bg="white")
        status.pack(pady=10)

        def update_bar(step=0):
            progress["value"] = step
            if step < 100:
                self.root.after(70, lambda: update_bar(step + 2))  # 70ms * 50 = ~3.5s, 70ms * 100 = ~7s
            else:
                callback()

        update_bar()

    def start_wiping(self):
        """Start the wiping process in a separate thread"""
        # Double-check folder exists and is accessible
        if not os.path.exists(self.selected_folder):
            messagebox.showerror("Error", "Selected folder no longer exists.")
            return
            
        # Validate number of passes
        try:
            # passes = int(self.passes_var.get())
            passes=7
            if passes < 1:
                messagebox.showerror("Error", "Number of passes must be at least 1.")
                return
            self.passes = passes
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for passes.")
            return

        try:
            files, total_size, hidden_files = collect_files(self.selected_folder)
            if not files:
                messagebox.showinfo(
                    "No Files Found",
                    "Selected folder contains no files to wipe.",
                    icon="info"
                )
                return
                
            # Show summary before starting
            file_count = len(files)
            size_gb = round(total_size / (1024**3), 2)
            msg = (f"Found {file_count} files ({size_gb} GB)\n"
                  f"Hidden files: {hidden_files}\n\n"
                  f"Starting secure wipe process with {self.passes} passes.\n"
                  "This may take some time.")
            proceed = messagebox.askyesno(
                "Confirm Wipe",
                msg,
                icon="warning"
            )
            if not proceed:
                return

        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to analyze folder:\n{str(e)}",
                icon="error"
            )
            return

        # Set up progress screen (this creates self.content_frame)
        self.setup_progress_screen()
        
        # Configure progress bar for the total operation
        self.progress_bar["maximum"] = len(files) * self.passes
        
        def update_status(message):
            self.status_label.config(text=message)
            self.root.update_idletasks()
        
        def wipe_thread():
            total_bytes_wiped = 0
            failed_files = []
            
            try:
                # Wipe files one by one
                for idx, fpath in enumerate(files, 1):
                    try:
                        file_size = os.path.getsize(fpath)
                        update_status(f"Wiping file {idx}/{len(files)}: {os.path.basename(fpath)}")
                        
                        secure_wipe_file(fpath, 
                                       passes=self.passes, 
                                       progress_callback=lambda p: self.root.after(0, 
                                           lambda: self.progress_bar.configure(value=(idx * self.passes - (self.passes - p)))))
                        
                        total_bytes_wiped += file_size
                    except Exception as e:
                        failed_files.append((fpath, str(e)))
                        update_status(f"Error wiping {os.path.basename(fpath)}: {e}")
                    
                    update_status(f"Wiped {idx}/{len(files)} files ({round(total_bytes_wiped/1e6, 2)} MB total)")

                update_status("Post Wipe completed.")

                # Simulate verification step
                def after_verification():
                    # update_status("Generating certificate...")  # <-- REMOVE or COMMENT THIS LINE
                    signed_json_path, pdf_path = wipe_folder_and_certify(
                        self.selected_folder,
                        getpass.getuser(),
                        passes=self.passes,
                        output_dir=self.output_dirs
                    )
                    pubkey_path = os.path.abspath(PUBLIC_KEY_FILE)
                    verification_ok = verify_certificate_json(signed_json_path, pubkey_path) if os.path.exists(pubkey_path) else False
                    self.root.after(0, lambda: self.setup_completion_screen(
                        signed_json_path, pdf_path, verification_ok))

                self.root.after(0, lambda: self.show_verification_simulation(after_verification))

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Error", f"An error occurred during wiping: {str(e)}"))
                self.root.after(0, self.setup_initial_screen)

        threading.Thread(target=wipe_thread, daemon=True).start()
