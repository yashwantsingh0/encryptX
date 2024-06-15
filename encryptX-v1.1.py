import sys
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget, QFileDialog, QMessageBox, QLineEdit
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("encryptX - Encryption/Decryption Tool 🔐")
        self.resize(550, 200)

        # Widgets
        self.label = QLabel("Enter Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.encrypt_button = QPushButton("Select file to Encrypt")
        self.decrypt_button = QPushButton("Select file to Decrypt")

        # Styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #292929;
                color: white;
            }
            QLabel, QPushButton {
                font-size: 22px;
                color: white;
            }
            QPushButton {
                padding: 10px 20px;
                background-color: #f0ad4e; /* Yellow */
                border: none;
                color: #292929; /* Dark background */
                text-align: center;
                text-decoration: none;
                font-size: 16px;
                margin: 4px 2px;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #ec971f; /* Darker yellow on hover */
            }
            QLineEdit {
                background-color: #383838; /* Dark grey for line edit */
                border: 1px solid #545454; /* Slightly lighter grey border */
                color: white;
                border-radius: 5px;
            }
            QMessageBox.information {
                background-color: #383838;
                color: white;
           }
        """)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Connect signals
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button.clicked.connect(self.decrypt_file)


    def encrypt_file(self):
        password = self.password_input.text()
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
                        n=2**14,
                        r=8,
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

    def decrypt_file(self):
        password = self.password_input.text()
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
                        n=2**14,
                        r=8,
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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
