import customtkinter as ctk
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
from datetime import datetime
import os
import base64  # Importing base64 module for encoding/decoding
import json
import logging
import pyperclip  # For copying to clipboard

# Configure logging
logging.basicConfig(filename='ciphersafe.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s')

# Set color theme
ctk.set_appearance_mode("dark")  # Options: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Options: "blue" (default), "green", "dark-blue"

# File to store the master password hash
MASTER_PASSWORD_FILE = 'master_password_hash.txt'

# Check for secure environment setup
def is_secure_environment():
    # Example security check based on environment variable
    secure_env = os.getenv('SECURE_ENV', 'false').lower() == 'true'
    if not secure_env:
        print("Warning: Running in an insecure environment. Set the 'SECURE_ENV' environment variable to 'true' for secure operations.")
    return secure_env

# Load or generate RSA keys
def load_or_generate_rsa_keys():
    if os.path.exists('rsa_private_key.pem'):
        with open('rsa_private_key.pem', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open('rsa_private_key.pem', 'wb') as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    return private_key, private_key.public_key()

# Load the master password hash from file
def load_master_password_hash():
    if os.path.exists(MASTER_PASSWORD_FILE):
        with open(MASTER_PASSWORD_FILE, 'r') as file:
            return file.read().strip()
    return None

# Save the master password hash to file
def save_master_password_hash(hash_value):
    with open(MASTER_PASSWORD_FILE, 'w') as file:
        file.write(hash_value)

# Master password management
MASTER_PASSWORD_HASH = load_master_password_hash()

def hash_password(password):
    """Hash the password using SHA-256."""
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(password.encode())
    return hasher.finalize().hex()

def verify_master_password(entered_password):
    """Verify the entered password against the stored hash."""
    if MASTER_PASSWORD_HASH is None:
        return False
    return hash_password(entered_password) == MASTER_PASSWORD_HASH

def set_master_password():
    """Prompt the user to set a new master password."""
    master_password = ctk.CTkInputDialog(text="Set a new master password:", title="Master Password Setup").get_input()
    if master_password is None:
        return False
    confirm_password = ctk.CTkInputDialog(text="Confirm master password:", title="Master Password Setup").get_input()
    if confirm_password is None or master_password != confirm_password:
        custom_message_box("Error", "Passwords do not match.")
        return False
    hash_value = hash_password(master_password)
    save_master_password_hash(hash_value)
    logging.info("Master password set successfully.")
    return True

# Ensure the secure environment
if not is_secure_environment():
    print("Running in an insecure environment. Proceed with caution.")

# Load the RSA keys
private_key, public_key = load_or_generate_rsa_keys()

# Connect to SQLite database
conn = sqlite3.connect('ciphersafe.db')
cursor = conn.cursor()

# Create table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    account TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    last_used TEXT NOT NULL
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

    try:
        aes_key = private_key.decrypt(
            rsa_encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        raise ValueError("Decryption failed. Invalid encryption key or corrupted data.")

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(aes_encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    password = unpadder.update(padded_data) + unpadder.finalize()

    return password.decode()

# Add a new password
def add_password():
    account = entry_account.get()
    username = entry_username.get()
    password = entry_password.get()
    last_used = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if account and username and password:
        encrypted_data = encrypt_password(password)
        encrypted_data_str = json.dumps(encrypted_data)
        cursor.execute('INSERT INTO passwords (account, username, password, last_used) VALUES (?, ?, ?, ?)', 
                       (account, username, encrypted_data_str, last_used))
        conn.commit()
        entry_account.delete(0, ctk.END)
        entry_username.delete(0, ctk.END)
        entry_password.delete(0, ctk.END)
        logging.info(f"Added password for account {account}.")
        custom_message_box('Success', 'Password added successfully!')
        update_account_buttons()
    else:
        custom_message_box('Error', 'Please fill out all fields.')

# Calculate time since last used
def calculate_time_since(last_used):
    last_used_time = datetime.strptime(last_used, '%Y-%m-%d %H:%M:%S')
    delta = datetime.now() - last_used_time
    days = delta.days
    seconds = delta.seconds
    if days > 0:
        return f"{days} day(s) ago"
    elif seconds >= 3600:
        return f"{seconds // 3600} hour(s) ago"
    elif seconds >= 60:
        return f"{seconds // 60} minute(s) ago"
    else:
        return "Just now"

# Update the account buttons on the main tab
def update_account_buttons():
    for widget in tab_accounts.winfo_children():
        widget.destroy()

    cursor.execute('SELECT id, account, username, last_used FROM passwords')
    records = cursor.fetchall()
    
    for record in records:
        id_, account, username, last_used = record
        last_used_display = calculate_time_since(last_used)

        button_text = f"{account}\n{username}\nLast Used: {last_used_display}"
        button = ctk.CTkButton(tab_accounts, text=button_text, 
                               command=lambda account=account: view_account_password(account))
        button.pack(pady=5, padx=10, fill='x')

# View the password for a selected account
def view_account_password(account):
    entered_password = ctk.CTkInputDialog(text="Enter Master Password:", title="Verify Master Password").get_input()
    if entered_password is None:
        return
    if verify_master_password(entered_password):
        cursor.execute('SELECT password FROM passwords WHERE account = ?', (account,))
        encrypted_data_str = cursor.fetchone()[0]
        encrypted_data = json.loads(encrypted_data_str)
        try:
            password = decrypt_password(encrypted_data)
        except ValueError as e:
            custom_message_box("Error", str(e))
            return

        # Create a pop-up to show password with copy and toggle options
        view_password_window = ctk.CTkToplevel()
        view_password_window.title(f"Password for {account}")

        label_account = ctk.CTkLabel(view_password_window, text=f"Account: {account}", font=('Arial', 14))
        label_account.pack(pady=10)

        label_password = ctk.CTkLabel(view_password_window, text='*' * len(password), font=('Arial', 14))
        label_password.pack(pady=10)

        show_password = False
        def on_toggle():
            nonlocal show_password
            show_password = not show_password
            toggle_password_visibility(label_password, password, show_password)
            if show_password:
                toggle_button.configure(text="Hide")
            else:
                toggle_button.configure(text="Show")

        toggle_button = ctk.CTkButton(view_password_window, text="Show", command=on_toggle)
        toggle_button.pack(pady=5)

        copy_button = ctk.CTkButton(view_password_window, text="Copy to Clipboard", command=lambda: copy_to_clipboard(password))
        copy_button.pack(pady=5)

        # Update last used time
        new_last_used = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('UPDATE passwords SET last_used = ? WHERE account = ?', (new_last_used, account))
        conn.commit()
        update_account_buttons()

        view_password_window.geometry("300x250")
    else:
        custom_message_box("Error", "Incorrect master password.")

# Copy password to clipboard
def copy_to_clipboard(text):
    pyperclip.copy(text)
    custom_message_box("Copied", "Password copied to clipboard")

# Function to show or hide the password
def toggle_password_visibility(label, password, show):
    if show:
        label.configure(text=password)
    else:
        label.configure(text='*' * len(password))

# Custom message box function
def custom_message_box(title, message):
    """Display a custom message box using CTkToplevel."""
    message_box = ctk.CTkToplevel()
    message_box.title(title)

    label_message = ctk.CTkLabel(message_box, text=message, font=('Arial', 12))
    label_message.pack(pady=20, padx=20)

    button_ok = ctk.CTkButton(message_box, text="OK", command=message_box.destroy)
    button_ok.pack(pady=10)

    message_box.geometry("300x150")
    message_box.mainloop()

# Function to create a master password entry pop-up
def create_master_password_popup():
    def on_submit():
        entered_password = entry_master_password.get()
        if verify_master_password(entered_password):
            master_password_window.destroy()
            main_app()
        else:
            custom_message_box("Error", "Incorrect master password. Please try again.")
            entry_master_password.delete(0, ctk.END)

    master_password_window = ctk.CTkToplevel()
    master_password_window.title("Master Password")

    label_instruction = ctk.CTkLabel(master_password_window, text="Enter Master Password", font=('Arial', 14))
    label_instruction.pack(pady=20)

    entry_master_password = ctk.CTkEntry(master_password_window, show='*')
    entry_master_password.pack(pady=10)

    button_submit = ctk.CTkButton(master_password_window, text="Submit", command=on_submit)
    button_submit.pack(pady=20)

    master_password_window.geometry("300x200")
    master_password_window.mainloop()

# Create the main application window
def main_app():
    global entry_account, entry_username, entry_password, tab_accounts
    root = ctk.CTk()
    root.title('CipherSafe')
    root.geometry('500x600')

    # Create tab view
    tab_view = ctk.CTkTabview(root)
    tab_view.pack(pady=20, padx=20, fill="both", expand=True)

    # Tab for listing accounts
    tab_accounts = tab_view.add("Accounts")

    # Tab for adding passwords
    tab_add = tab_view.add("Add Password")

    label_title = ctk.CTkLabel(tab_add, text='Add New Password', font=('Arial', 20))
    label_title.pack(pady=10)

    label_account = ctk.CTkLabel(tab_add, text='Account')
    label_account.pack(pady=(10, 0))

    entry_account = ctk.CTkEntry(tab_add, placeholder_text='Enter account name')
    entry_account.pack(pady=5, fill='x')

    label_username = ctk.CTkLabel(tab_add, text='Username')
    label_username.pack(pady=(10, 0))

    entry_username = ctk.CTkEntry(tab_add, placeholder_text='Enter username')
    entry_username.pack(pady=5, fill='x')

    label_password = ctk.CTkLabel(tab_add, text='Password')
    label_password.pack(pady=(10, 0))

    entry_password = ctk.CTkEntry(tab_add, show='*', placeholder_text='Enter password')
    entry_password.pack(pady=5, fill='x')

    button_add = ctk.CTkButton(tab_add, text='Add Password', command=add_password)
    button_add.pack(pady=10)

    update_account_buttons()

    root.mainloop()

# Initialize the Tkinter root (required for CTkInputDialog to work)
app = ctk.CTk()  # Initialize the CTk application
app.withdraw()  # Hide the main window

# Verify master password on startup
if MASTER_PASSWORD_HASH is None:
    if set_master_password():
        create_master_password_popup()
else:
    create_master_password_popup()

# Close database connection when the application is closed
conn.close()
