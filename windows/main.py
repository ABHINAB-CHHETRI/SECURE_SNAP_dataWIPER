import sys
import os
import getpass
import datetime
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QFileDialog, QProgressBar,
    QLineEdit, QFormLayout, QMessageBox, QSpinBox, QHBoxLayout
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from files_utils import collect_files,secure_wipe_file
from wipe_process import wipe_folder_and_certify
from crypto_utils import verify_certificate_json, PUBLIC_KEY_FILE

class MainWindow(QWidget):
    def _wipe_animation(self):
        # Simple animation: rotating bar
        anim_chars = ['|', '/', '-', '\\']
        idx = getattr(self, '_anim_idx', 0)
        self.progress.setFormat(f"Wiping... {anim_chars[idx % len(anim_chars)]}")
        self._anim_idx = idx + 1

    def __init__(self):
        super().__init__()
        self.setWindowTitle('SecureErase')
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel('SecureErase')
        title.setFont(QFont('Arial', 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.form_layout = QFormLayout()
        self.name_input = QLineEdit(getpass.getuser())
        self.org_input = QLineEdit()
        self.email_input = QLineEdit()
        self.phone_input = QLineEdit()
        self.location_input = QLineEdit()
        self.form_layout.addRow('Operator Name:', self.name_input)
        self.form_layout.addRow('Organization:', self.org_input)
        self.form_layout.addRow('Email:', self.email_input)

        pass_layout = QHBoxLayout()
        pass_label = QLabel('Number of Wipe Passes:')
        self.pass_spin = QSpinBox()
        self.pass_spin.setRange(1, 100)
        self.pass_spin.setValue(7)
        pass_layout.addWidget(pass_label)
        pass_layout.addWidget(self.pass_spin)
        layout.addLayout(pass_layout)

        self.info_label = QLabel('Select a folder to securely erase all files (DESTRUCTIVE).')
        layout.addWidget(self.info_label)
        self.choose_button = QPushButton('Choose Folder to Wipe')
        self.choose_button.clicked.connect(self.choose_folder)
        layout.addWidget(self.choose_button)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.certificate_label = QLabel('')
        self.certificate_label.setWordWrap(True)
        layout.addWidget(self.certificate_label)

        self.setLayout(layout)

    def choose_folder(self):
        class WipeThread(QThread):
            progress = pyqtSignal(int)
            finished = pyqtSignal(str, str, bool)
            def __init__(self, files, folder_path, operator_id, passes, output_dirs):
                super().__init__()
                self.files = files
                self.folder_path = folder_path
                self.operator_id = operator_id
                self.passes = passes
                self.output_dirs = output_dirs
            def run(self):
                # Wipe files one by one, emit progress
                for idx, fpath in enumerate(self.files):
                    try:
                        secure_wipe_file(fpath, passes=self.passes)
                    except Exception:
                        pass
                    self.progress.emit(idx+1)
                # After wipe, generate certificate
                signed_json_path, pdf_path = wipe_folder_and_certify(
                    self.folder_path,
                    self.operator_id,
                    passes=self.passes,
                    output_dir=self.output_dirs
                )
                pubkey_path = os.path.abspath(PUBLIC_KEY_FILE)
                ok = verify_certificate_json(signed_json_path, pubkey_path) if os.path.exists(pubkey_path) else False
                self.finished.emit(signed_json_path, pdf_path, ok)

        folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder to Wipe')
        if not folder_path:
            return

        # double-confirm
        resp = QMessageBox.question(self, "Confirm Wipe",
                                    f"Do you REALLY want to permanently wipe ALL files in:\n\n{folder_path}\n\nThis action is irreversible.",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if resp != QMessageBox.Yes:
            return
        files, total_size, hidden_files = collect_files(folder_path)
        if not files:
            QMessageBox.information(self, "Nothing to wipe", "Selected folder contains no files.")
            return

        self.progress.setMaximum(len(files))
        self.progress.setValue(0)
        self.progress.setFormat("Wiping... |")
        self._anim_idx = 0
        self.choose_button.setEnabled(False)
        self.progress.setVisible(True)
        self.certificate_label.setText("")

        operator_id = self.name_input.text() or getpass.getuser()
        output_dirs = {"json": os.path.join("output", "json"), "pdf": os.path.join("output", "pdf")}
        self.wipe_thread = WipeThread(files, folder_path, operator_id, self.pass_spin.value(), output_dirs)
        self.wipe_thread.progress.connect(self._on_wipe_progress)
        self.wipe_thread.finished.connect(self._on_wipe_finished)
        self.wipe_thread.start()

        # Animation timer
        from PyQt5.QtCore import QTimer
        self.anim_timer = QTimer()
        self.anim_timer.timeout.connect(self._wipe_animation)
        self.anim_timer.start(150)

    def _on_wipe_progress(self, value):
        self.progress.setValue(value)
    def _on_wipe_finished(self, signed_json_path, pdf_path, ok):
        self.anim_timer.stop()
        self.progress.setFormat("")
        self.choose_button.setEnabled(True)
        if ok:
            msg = f"Wipe complete. Certificate generated and signature VERIFIED.\n\nCertificate: {signed_json_path}\nPDF: {pdf_path}"
        else:
            msg = f"Wipe complete. Certificate generated but signature VERIFICATION FAILED.\n\nCertificate: {signed_json_path}\nPDF: {pdf_path}"
        self.certificate_label.setText(msg.replace("\n", "<br>"))
        QMessageBox.information(self, "Wipe Complete", msg)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
