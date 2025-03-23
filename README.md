# Password Manager

**Disclaimer:**  
This password manager is provided for educational purposes.  
Do **NOT** use it to store sensitive data without understanding its limitations. The author is not responsible  
for any misuse or data loss.

## Overview

This project implements a command-line password manager in a novel way. It uses the Python [cryptography](https://cryptography.io/en/latest/) library to encrypt all stored passwords using a key derived from your master password (via PBKDF2). Credentials are stored in an SQLite database. Features include:

- Adding, viewing, updating, and deleting credentials.
- Secure encryption/decryption of passwords.
- Random password generation.

## Requirements

- **Operating System:** Linux, macOS, or Windows (with Python 3 installed)
- **Python Version:** 3.6 or above
- **Libraries:** See `requirements.txt`

## Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/novel-password-manager.git
   cd novel-password-manager

Install dependencies:

```bash
make install
```
Usage
Run the password manager with:

```bash
make run
```

You will be prompted for your master password. The master password is used to derive the encryption key to protect your stored credentials. Once inside, you can choose from the menu options to add, view, update, or delete credentials, as well as generate random passwords.

Security Notice
Master Password:
Keep your master password secure and never share it.

Encryption:
The passwords are encrypted using Fernet (AES in CBC mode with HMAC) but be aware that this is a learning tool.

Usage:
Use this tool only on systems you own or have explicit permission to manage credentials.

License
![MIT License]().

