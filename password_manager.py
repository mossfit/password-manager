#!/usr/bin/env python3
import os
import sqlite3
import base64
import getpass
import secrets
import string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Files and constants
DB_FILE = "passwords.db"
SALT_FILE = "salt.bin"
ITERATIONS = 100_000

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derives a Fernet-compatible key from the master password and salt using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def load_or_create_salt() -> bytes:
    """
    Loads the salt from file, or creates it if it doesn't exist.
    """
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    return salt

def init_db():
    """
    Creates the SQLite database and table if not already present.
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def add_credential(fernet: Fernet):
    """
    Adds a new credential to the database.
    """
    service = input("Service: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password (leave blank to generate): ").strip()
    if not password:
        password = generate_password()
        print("Generated password:", password)

    encrypted_password = fernet.encrypt(password.encode()).decode()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO credentials (service, username, password) VALUES (?, ?, ?)",
                (service, username, encrypted_password))
    conn.commit()
    conn.close()
    print("Credential added successfully.")

def view_credentials(fernet: Fernet):
    """
    Retrieves and displays all stored credentials.
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, service, username, password FROM credentials")
    rows = cur.fetchall()
    conn.close()
    if not rows:
        print("No credentials stored.")
        return

    print("{:<5} {:<20} {:<20} {:<30}".format("ID", "Service", "Username", "Password"))
    print("-" * 75)
    for row in rows:
        try:
            decrypted_pass = fernet.decrypt(row[3].encode()).decode()
        except Exception as e:
            decrypted_pass = "Error decrypting"
        print("{:<5} {:<20} {:<20} {:<30}".format(row[0], row[1], row[2], decrypted_pass))

def delete_credential():
    """
    Deletes a credential by ID.
    """
    cred_id = input("Enter credential ID to delete: ").strip()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
    if cur.rowcount == 0:
        print("No credential found with that ID.")
    else:
        print("Credential deleted successfully.")
    conn.commit()
    conn.close()

def update_credential(fernet: Fernet):
    """
    Updates an existing credential.
    """
    cred_id = input("Enter credential ID to update: ").strip()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id FROM credentials WHERE id = ?", (cred_id,))
    if not cur.fetchone():
        print("No credential found with that ID.")
        conn.close()
        return

    service = input("New Service (leave blank to keep current): ").strip()
    username = input("New Username (leave blank to keep current): ").strip()
    password = getpass.getpass("New Password (leave blank to generate and update): ").strip()
    if password == "":
        password = generate_password()
        print("Generated password:", password)
    encrypted_password = fernet.encrypt(password.encode()).decode()

    # Update only non-empty fields; for simplicity, we update all fields here.
    cur.execute("""
        UPDATE credentials
        SET service = COALESCE(NULLIF(?, ''), service),
            username = COALESCE(NULLIF(?, ''), username),
            password = ?
        WHERE id = ?
    """, (service, username, encrypted_password, cred_id))
    conn.commit()
    conn.close()
    print("Credential updated successfully.")

def generate_password(length: int = 16) -> str:
    """
    Generates a random password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def menu(fernet: Fernet):
    """
    Displays the menu and routes user commands.
    """
    options = {
        "1": ("Add Credential", lambda: add_credential(fernet)),
        "2": ("View Credentials", lambda: view_credentials(fernet)),
        "3": ("Update Credential", lambda: update_credential(fernet)),
        "4": ("Delete Credential", delete_credential),
        "5": ("Generate Password", lambda: print("Generated password:", generate_password())),
        "6": ("Exit", None)
    }

    while True:
        print("\n=== Password Manager Menu ===")
        for key, (desc, _) in options.items():
            print(f"{key}. {desc}")
        choice = input("Enter your choice: ").strip()
        if choice == "6":
            print("Exiting...")
            break
        elif choice in options:
            options[choice][1]()
        else:
            print("Invalid choice. Please try again.")

def main():
    # Initialize salt and database
    salt = load_or_create_salt()
    init_db()

    # Prompt for the master password and derive encryption key.
    master_password = getpass.getpass("Enter master password: ").strip()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    # Show the main menu.
    menu(fernet)

if __name__ == "__main__":
    main()
