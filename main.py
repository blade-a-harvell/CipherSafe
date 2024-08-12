import customtkinter as ctk
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
import os
import base64  # Importing base64 module for encoding/decoding
from tkinter import messagebox
from getpass import getpass
import json
import logging

# Configure logging
logging.basicConfig(filename='password_manager.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s')

# Check for secure environment setup
def is_secure_environment():
    # Example security check based on environment variable
    secure_env = os.getenv('SECURE_ENV', 'false').lower() == 'true'
    if not secure_env:
        print("Warning: Running in an insecure environment. Set the 'SECURE_ENV' environment variable to 'true' for secure operations.")
    return secure_env

# Load or generate RSA keys
def load_or_generate_rsa_keys():
    if 'RSA_PRIVATE_KEY' in os.environ:
        private_key = serialization.load_pem_private_key(
            os.environ['RSA_PRIVATE_KEY'].encode(),
            password=None,
            backend=default_backend()
        )
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        os.environ['RSA_PRIVATE_KEY'] = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    return private_key, private_key.public_key()

# Master password management
MASTER_PASSWORD_HASH = os.getenv('MASTER_PASSWORD_HASH', None)

def verify_master_password():
    if MASTER_PASSWORD_HASH is None:
        return False
    master_password = getpass("Enter master password: ")
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(master_password.encode())
    return hasher.finalize() == bytes.fromhex(MASTER_PASSWORD_HASH)

def set_master_password():
    if MASTER_PASSWORD_HASH is None:
        master_password = getpass("Set a new master password: ")
        confirm_password = getpass("Confirm master password: ")
        if master_password != confirm_password:
            raise ValueError("Passwords do not match.")
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(master_password.encode())
        hash_value = hasher.finalize().hex()
        os.environ['MASTER_PASSWORD_HASH'] = hash_value
        logging.info("Master password set successfully.")

# Ensure the secure environment
if not is_secure_environment():
    print("Running in an insecure environment. Proceed with caution.")
    # Optionally, you can still choose to raise an error in production environments:
    # raise EnvironmentError("Insecure environment detected. Set up a secure environment first.")

# Load the RSA keys
private_key, public_key = load_or_generate_rsa_keys()

# Connect to SQLite database
conn = sqlite3.connect('password_manager.db')
cursor = conn.cursor()

# Create table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )''')
conn.commit()

# Encrypt the password
def encrypt_password(password):
    aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)  # Initialization vector
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    aes_encrypted = encryptor.update(padded_data) + encryptor.finalize()

    rsa_encrypted_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(aes_encrypted)
    hashed_password = digest.finalize()

    encrypted_data = {
        'iv': base64.b64encode(iv).decode(),
        'aes_encrypted': base64.b64encode(aes_encrypted).decode(),
        'rsa_encrypted_key': base64.b64encode(rsa_encrypted_key).decode(),
        'hashed_password': base64.b64encode(hashed_password).decode()
    }

    return encrypted_data

# Decrypt the password
def decrypt_password(encrypted_data):
    iv = base64.b64decode(encrypted_data['iv'])
    aes_encrypted = base64.b64decode(encrypted_data['aes_encrypted'])
    rsa_encrypted_key = base64.b64decode(encrypted_data['rsa_encrypted_key'])

    aes_key = private_key.decrypt(
        rsa_encrypted_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(aes_encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    password = unpadder.update(padded_data) + unpadder.finalize()

    return password.decode()

# Add a new password
def add_password():
    service = entry_service.get()
    username = entry_username.get()
    password = entry_password.get()
    
    if service and username and password:
        encrypted_data = encrypt_password(password)
        encrypted_data_str = json.dumps(encrypted_data)
        cursor.execute('INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)', (service, username, encrypted_data_str))
        conn.commit()
        entry_service.delete(0, ctk.END)
        entry_username.delete(0, ctk.END)
        entry_password.delete(0, ctk.END)
        logging.info(f"Added password for service {service}.")
        messagebox.showinfo('Success', 'Password added successfully!')
    else:
        messagebox.showwarning('Error', 'Please fill out all fields.')

# View passwords
def view_passwords():
    cursor.execute('SELECT service, username, password FROM passwords')
    records = cursor.fetchall()
    
    listbox.delete("1.0", ctk.END)
    for record in records:
        service, username, encrypted_data_str = record
        try:
            encrypted_data = json.loads(encrypted_data_str)
            password = decrypt_password(encrypted_data)
            listbox.insert(ctk.END, f'Service: {service}, Username: {username}, Password: {password}\n')
        except Exception as e:
            listbox.insert(ctk.END, f'Error decrypting password for {service}: {e}\n')

# Create the main window with customtkinter
ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

root = ctk.CTk()
root.title('Password Manager')

# Create UI components
frame = ctk.CTkFrame(root)
frame.pack(pady=20, padx=20, fill="both", expand=True)

label_title = ctk.CTkLabel(frame, text='Password Manager', font=('Arial', 20))
label_title.pack(pady=10)

label_service = ctk.CTkLabel(frame, text='Service')
label_service.pack(pady=(10, 0))

entry_service = ctk.CTkEntry(frame, placeholder_text='Enter service name')
entry_service.pack(pady=5, fill='x')

label_username = ctk.CTkLabel(frame, text='Username')
label_username.pack(pady=(10, 0))

entry_username = ctk.CTkEntry(frame, placeholder_text='Enter username')
entry_username.pack(pady=5, fill='x')

label_password = ctk.CTkLabel(frame, text='Password')
label_password.pack(pady=(10, 0))

entry_password = ctk.CTkEntry(frame, show='*', placeholder_text='Enter password')
entry_password.pack(pady=5, fill='x')

button_add = ctk.CTkButton(frame, text='Add Password', command=add_password)
button_add.pack(pady=10)

button_view = ctk.CTkButton(frame, text='View Passwords', command=view_passwords)
button_view.pack(pady=5)

listbox = ctk.CTkTextbox(root, width=500, height=200)
listbox.pack(pady=10, padx=20, fill="both", expand=True)

# Verify master password on startup
if not verify_master_password():
    if MASTER_PASSWORD_HASH is None:
        set_master_password()
    else:
        raise ValueError("Incorrect master password.")

# Start the main loop
root.mainloop()

# Close database connection when the application is closed
conn.close()
