# app.py — QR Password Locker 🔐
import os
import json
import base64
import qrcode
from cryptography.fernet import Fernet

# === File Names ===
KEY_FILE = "secret.key"
VAULT_FILE = "vault.json"
QR_FILE = "unlock_key.png"

# === Load or Create Encryption Key ===
def load_key():
    """Load the AES key, or create and save a new one if missing."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

# Load key and initialize encryption engine
key = load_key()
fernet = Fernet(key)

# === Save a New Password Entry ===
def save_password(platform, username, password):
    """Encrypt and store password entry in vault."""
    encrypted = fernet.encrypt(password.encode()).decode()
    entry = {"username": username, "password": encrypted}

    vault = {}
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as f:
            vault = json.load(f)

    vault[platform] = entry

    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=4)

# === Load and Decrypt All Passwords ===
def load_passwords():
    """Return all saved passwords decrypted."""
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "r") as f:
        vault = json.load(f)

    decrypted = {}
    for platform, data in vault.items():
        username = data["username"]
        password = fernet.decrypt(data["password"].encode()).decode()
        decrypted[platform] = {"username": username, "password": password}

    return decrypted

# === Generate QR Code for Unlock Key ===
def generate_qr_key():
    """Generate a QR code that encodes the secret key (base64)."""
    key_b64 = base64.urlsafe_b64encode(key).decode()
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(key_b64)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(os.path.join(os.getcwd(), QR_FILE))

# === Unlock From QR Key (Optional Recovery) ===
def unlock_with_key(b64_key):
    """Accept a base64 key string and initialize Fernet engine."""
    decoded_key = base64.urlsafe_b64decode(b64_key)
    return Fernet(decoded_key)