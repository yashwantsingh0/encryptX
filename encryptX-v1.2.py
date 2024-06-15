# Created by Yashwant Singh on June 15, 2024.
import sys
import re
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, 
                             QWidget, QFileDialog, QMessageBox, QLineEdit, QProgressBar)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("encryptX - Encryption/Decryption Tool 🔐")
        self.resize(550, 250)

        # Widgets
        self.label = QLabel("Enter your password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        self.confirm_label = QLabel("Confirm your password:")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        
        self.encrypt_button = QPushButton("Select file to Encrypt")
        self.decrypt_button = QPushButton("Select file to Decrypt")
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)

        # Styling with Monokai theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #272822; /* Dark grey */
                color: white;
            }
            QLabel, QPushButton {
                font-size: 22px;
                color: white;
            }
            QPushButton {
                padding: 10px 20px;
                background-color: #26f9f2; /* Sky Blue */
                border: none;
                color: #272822; /* Dark background */
                text-align: center;
                text-decoration: none;
                font-size: 16px;
                margin: 4px 2px;
                border-radius: 10px;
                /* Neon blue glow effect */
                box-shadow: 0 0 20px #66d9ef;
            }
            QPushButton:hover {
                background-color: #00e1b0; /* Lighter pink on hover */
            }
            QLineEdit {
                background-color: #383830; /* Dark greenish grey for line edit */
                border: 1px solid #49483e; /* Slightly lighter grey border */
                color: white;
                border-radius: 5px;
            }
            QProgressBar {
                text-align: center;
                background-color: #383830; /* Dark greenish grey */
                border: 1px solid #49483e; /* Slightly lighter grey border */
                color: white;
                border-radius: 5px;
            }
            QMessageBox {
                background-color: #272822; /* Dark grey */
            }
        """)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_label)
        layout.addWidget(self.confirm_password_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.progress_bar)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Connect signals
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button.clicked.connect(self.decrypt_file)

    def validate_password(self, password):
        """
        Validate the password to ensure it meets security requirements.
        Password must be at least 8 characters long, contain at least one digit,
        one special character, and a mix of uppercase and lowercase letters.
        """
        if len(password) < 8:
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        return True

    def encrypt_file(self):
        """
        Encrypt the selected file using AES-256 in CFB mode with PKCS7 padding.
        Derive the encryption key using Scrypt KDF with a random salt.
        """
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        if not password or not confirm_password:
            QMessageBox.warning(self, "Invalid Password", "Password fields must not be empty.")
            return
        if password != confirm_password:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return
        if not self.validate_password(password):
            QMessageBox.warning(self, "Invalid Password", "Password must be at least 8 characters long, contain at least one digit, one special character, and a mix of uppercase and lowercase letters.")
            return

        input_file, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if input_file:
            output_file, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File As")
            if output_file:
                try:
                    # Generate a random salt
                    salt = urandom(16)
                    
                    # Derive key from password and salt
                    kdf = Scrypt(
                        salt=salt,
                        length=32,
                        n=2**20,  # Increased for stronger security
                        r=16,     # Increased for stronger security
                        p=1,
                        backend=default_backend()
                    )
                    key = kdf.derive(password.encode())
                    
                    # Generate a random initialization vector (IV)
                    iv = urandom(16)

                    # Pad the plaintext
                    padder = padding.PKCS7(128).padder()
                    with open(input_file, 'rb') as f_in:
                        plaintext = f_in.read()
                    padded_plaintext = padder.update(plaintext) + padder.finalize()

                    # Encrypt the plaintext
                    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                    encryptor = cipher.encryptor()
                    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

                    # Write salt, IV, and ciphertext to the output file
                    with open(output_file, 'wb') as f_out:
                        f_out.write(salt)
                        f_out.write(iv)
                        f_out.write(ciphertext)
                    
                    QMessageBox.information(self, "Encryption", "File encryption successful!")
                except Exception as e:
                    QMessageBox.critical(self, "Encryption Failed!", str(e))

        # Update the progress bar
        progress_step = 0
        total_steps = 100  # Adjust based on your file processing steps
        self.progress_bar.setValue(progress_step)

        try:
            # Perform encryption steps
            ...

            # Example of updating progress
            progress_step += 25  # Update based on the actual progress
            self.progress_bar.setValue(progress_step)

            # Final progress update
            self.progress_bar.setValue(100)

            QMessageBox.information(self, "Encryption", "File encryption successful!")
        except Exception as e:
            QMessageBox.critical(self, "Encryption Failed!", str(e))

    def decrypt_file(self):
        """
        Decrypt the selected file using AES-256 in CFB mode with PKCS7 padding.
        Derive the decryption key using Scrypt KDF with the stored salt.
        """
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        if not password or not confirm_password:
            QMessageBox.warning(self, "Invalid Password", "Password fields must not be empty.")
            return
        if password != confirm_password:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return
        if not self.validate_password(password):
            QMessageBox.warning(self, "Invalid Password", "Password must be at least 8 characters long, contain at least one digit, one special character, and a mix of uppercase and lowercase letters.")
            return
        
        input_file, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if input_file:
            output_file, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File As")
            if output_file:
                try:
                    # Read salt, IV, and ciphertext from the input file
                    with open(input_file, 'rb') as f_in:
                        salt = f_in.read(16)
                        iv = f_in.read(16)
                        ciphertext = f_in.read()
                    
                    # Derive key from password and salt
                    kdf = Scrypt(
                        salt=salt,
                        length=32,
                        n=2**20,  # Increased for stronger security
                        r=16,     # Increased for stronger security
                        p=1,
                        backend=default_backend()
                    )
                    key = kdf.derive(password.encode())

                    # Decrypt the ciphertext
                    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                    # Unpad the plaintext
                    unpadder = padding.PKCS7(128).unpadder()
                    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

                    # Write the plaintext to the output file
                    with open(output_file, 'wb') as f_out:
                        f_out.write(plaintext)
                    
                    QMessageBox.information(self, "Decryption", "File decryption successful!")
                except Exception as e:
                    QMessageBox.critical(self, "Decryption Failed", str(e))

        # Update the progress bar
        progress_step = 0
        total_steps = 100  # Adjust based on your file processing steps
        self.progress_bar.setValue(progress_step)

        try:
            # Perform decryption steps
            ...

            # Example of updating progress
            progress_step += 25  # Update based on the actual progress
            self.progress_bar.setValue(progress_step)

            # Final progress update
            self.progress_bar.setValue(100)

            QMessageBox.information(self, "Decryption", "File decryption successful!")
        except Exception as e:
            QMessageBox.critical(self, "Decryption Failed", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
