"""
=============================================================================
Template: DES-CBC Encryption + SHA-256 Hashing + ElGamal Signature + RBAC
=============================================================================
PURPOSE:
This program simulates a secure Role-Based Access Control (RBAC) system.

ALGORITHMS & WHY:
- DES-CBC: Symmetric encryption for data confidentiality.
- SHA-256: Cryptographic hash function for data integrity.
- ElGamal Digital Signature: Asymmetric signature for non-repudiation and origin authentication.

ROLES:
- Uploader: Uploads and secures data.
- Reviewer: Verifies and decrypts data.
- Auditor: Verifies data but cannot decrypt.

HOW TO RUN:
Run normally, use sample credentials: user1 (uploader), user2 (reviewer), user3 (auditor) with password '123'.

# CUSTOMIZE: Users, roles, keys, storage file, and ElGamal parameters can be customized below.
"""

import hashlib
import pickle
import datetime
import math
import random
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================

# Access control: Defines system users, passwords, and assigned roles.
# CUSTOMIZE: Users and Roles
USERS = {
    "user1": {"password": "123", "role": "Role1"},
    "user2": {"password": "123", "role": "Role2"},
    "user3": {"password": "123", "role": "Role3"}
}

# Access control: Maps internal role IDs to human-readable role names.
# CUSTOMIZE: Role names
ROLE_NAMES = {
    "Role1": "uploader",
    "Role2": "reviewer",
    "Role3": "auditor"
}

# CUSTOMIZE: Storage file
STORAGE_FILE = "storage.pkl" # File used to persist records

# CUSTOMIZE: DES Key and IV
# Must be exactly 8 bytes for DES
CIPHER_KEY = b"12345678"
IV = b"12345678"

# CUSTOMIZE: ElGamal Parameters (Educational)
ELGAMAL_P = 7919 # A prime number
ELGAMAL_G = 2    # A primitive root modulo P
ELGAMAL_X = 3456 # Private key
ELGAMAL_Y = pow(ELGAMAL_G, ELGAMAL_X, ELGAMAL_P) # Public key y = g^x mod p

# ==========================================
# CRYPTOGRAPHIC FUNCTIONS
# ==========================================

def encrypt_des_cbc(data_str: str) -> bytes:
    """
    Encrypts a plaintext string using DES in CBC mode.
    Parameters:
      data_str: The plaintext string to encrypt.
    Returns:
      The encrypted bytes (ciphertext).
    """
    # Create a new DES cipher instance using the key and IV
    cipher = DES.new(CIPHER_KEY, DES.MODE_CBC, IV)
    # Pad the encoded string to the DES block size and encrypt
    return cipher.encrypt(pad(data_str.encode(), DES.block_size))

def decrypt_des_cbc(ciphertext: bytes) -> str:
    """
    Decrypts ciphertext bytes using DES in CBC mode.
    Parameters:
      ciphertext: The encrypted bytes.
    Returns:
      The decrypted plaintext string.
    """
    # Create a new DES cipher instance using the key and IV
    cipher = DES.new(CIPHER_KEY, DES.MODE_CBC, IV)
    # Decrypt and unpad to retrieve original string
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()

def compute_hash(data: bytes) -> str:
    """
    Computes the SHA-256 hash of the given bytes.
    Parameters:
      data: The input bytes.
    Returns:
      A hex string representation of the hash.
    """
    # Use hashlib to compute the SHA-256 digest
    return hashlib.sha256(data).hexdigest()

def gcd(a, b):
    """
    Computes the Greatest Common Divisor of a and b.
    Parameters:
      a, b: integers.
    Returns:
      The GCD of a and b.
    """
    # Euclidean algorithm
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """
    Computes the modular multiplicative inverse of a modulo m.
    Parameters:
      a: The integer.
      m: The modulus.
    Returns:
      The modular inverse.
    """
    # Extended Euclidean algorithm
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def elgamal_sign(data: bytes):
    """
    Signs data using the ElGamal Digital Signature algorithm.
    Parameters:
      data: The input data to sign.
    Returns:
      A tuple (r, s) representing the signature.
    """
    # Step 1: Hash the data and convert to integer
    h_int = int(compute_hash(data), 16)
    
    # Step 2: Choose a random k coprime to P-1
    while True:
        k = random.randint(2, ELGAMAL_P - 2)
        if gcd(k, ELGAMAL_P - 1) == 1:
            break
            
    # ElGamal Signature Math:
    # r = g^k mod p (First part of signature)
    r = pow(ELGAMAL_G, k, ELGAMAL_P)
    
    # k_inv = k^-1 mod (p-1) (Modular inverse of k)
    k_inv = mod_inverse(k, ELGAMAL_P - 1)
    
    # s = (h - x*r) * k^-1 mod (p-1) (Second part of signature)
    s = ((h_int - ELGAMAL_X * r) * k_inv) % (ELGAMAL_P - 1)
    
    return r, s

def elgamal_verify(data: bytes, r: int, s: int, y: int) -> bool:
    """
    Verifies an ElGamal Digital Signature.
    Parameters:
      data: The original data.
      r, s: The signature parts.
      y: The public key.
    Returns:
      True if valid, False otherwise.
    """
    # Step 1: Validate ranges for r and s
    if not (0 < r < ELGAMAL_P and 0 < s < ELGAMAL_P - 1):
        return False
        
    # Step 2: Compute hash of the data
    h_int = int(compute_hash(data), 16)
    
    # ElGamal Verification Math:
    # Check if g^h mod p == (y^r * r^s) mod p
    # v1 = g^h mod p
    v1 = pow(ELGAMAL_G, h_int, ELGAMAL_P)
    
    # v2 = (y^r * r^s) mod p
    v2 = (pow(y, r, ELGAMAL_P) * pow(r, s, ELGAMAL_P)) % ELGAMAL_P
    
    return v1 == v2

# ==========================================
# STORAGE HELPERS
# ==========================================

def load_records():
    """
    Loads saved records from the storage file.
    Returns:
      A list of record dictionaries.
    """
    # If the file doesn't exist, return an empty list
    if not os.path.exists(STORAGE_FILE):
        return []
    # Open the file in binary read mode
    with open(STORAGE_FILE, "rb") as f:
        return pickle.load(f)

def save_records(records):
    """
    Saves records to the storage file.
    Parameters:
      records: The list of records to save.
    Returns:
      None
    """
    # Open the file in binary write mode
    with open(STORAGE_FILE, "wb") as f:
        pickle.dump(records, f)

def select_record(records):
    """
    Displays a list of records and prompts the user to select one.
    Parameters:
      records: List of records.
    Returns:
      The selected record, or None if invalid.
    """
    if not records:
        print("No records available.")
        return None
    # Enumerate through records and print timestamps
    for idx, r in enumerate(records):
        print(f"[{idx}] Record from {r['timestamp']}")
    choice = input("Select record number: ")
    try:
        idx = int(choice)
        return records[idx]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return None

# ==========================================
# ROLE ACTIONS (RBAC)
# ==========================================

def role1_action(username: str):
    """
    Role1 Action (Uploader): Uploads and secures sensitive data.
    Parameters:
      username: The logged-in user's name.
    Returns:
      None
    """
    # Access control: Only executed by Role1 (Uploader)
    data = input("Enter sensitive data to upload: ")
    
    # Step 1: Encrypt the data
    encrypted_data = encrypt_des_cbc(data)
    
    # Step 2: Sign the encrypted data
    r, s = elgamal_sign(encrypted_data)
    
    # Step 3: Compute the hash of the encrypted data
    h = compute_hash(encrypted_data)
    
    # Step 4: Construct the record metadata
    record = {
        "encrypted_data": encrypted_data,
        "hash": h,
        "signature": (r, s),
        "elgamal_public_key": (ELGAMAL_P, ELGAMAL_G, ELGAMAL_Y),
        "timestamp": datetime.datetime.now().isoformat(),
        "uploader": username
    }
    
    # Step 5: Save the record
    records = load_records()
    records.append(record)
    save_records(records)
    print("Record encrypted, hashed, signed, and saved!")

def role2_action():
    """
    Role2 Action (Reviewer): Verifies integrity and signature, then decrypts.
    Parameters:
      None
    Returns:
      None
    """
    # Access control: Only executed by Role2 (Reviewer)
    records = load_records()
    record = select_record(records)
    if not record: return
    
    # Extract fields from the record
    enc_data = record["encrypted_data"]
    stored_hash = record["hash"]
    r, s = record["signature"]
    p, g, y = record["elgamal_public_key"]
    
    # Verification Flow: Verify before decrypting
    current_hash = compute_hash(enc_data)
    print("--- Verification ---")
    
    # Step 1: Check data integrity (hash comparison)
    integrity_pass = (current_hash == stored_hash)
    print(f"Integrity check: {'PASS' if integrity_pass else 'FAIL'}")
    
    # Step 2: Check digital signature
    sig_pass = elgamal_verify(enc_data, r, s, y)
    print(f"Signature check: {'PASS' if sig_pass else 'FAIL'}")
    
    # Step 3: Conditional decryption (only if verification passed)
    if integrity_pass and sig_pass:
        print("--- Decrypted Content ---")
        try:
            print(decrypt_des_cbc(enc_data))
        except Exception as e:
            print(f"Decryption failed: {e}")
    else:
        # Tampering or corruption detected
        print("Verification failed! Will not decrypt.")

def role3_action():
    """
    Role3 Action (Auditor): Audits metadata and verifies signature without decrypting.
    Parameters:
      None
    Returns:
      None
    """
    # Access control: Only executed by Role3 (Auditor)
    records = load_records()
    record = select_record(records)
    if not record: return
    
    # Extract fields
    enc_data = record["encrypted_data"]
    r, s = record["signature"]
    p, g, y = record["elgamal_public_key"]
    
    # Step 1: Display metadata
    print("--- Metadata ---")
    print(f"Timestamp: {record['timestamp']}")
    print(f"Uploader: {record['uploader']}")
    print(f"Signature: r={r}, s={s}")
    
    # Step 2: Verify signature
    sig_pass = elgamal_verify(enc_data, r, s, y)
    print(f"Signature check: {'PASS' if sig_pass else 'FAIL'}")
    
    # Access control constraint: Auditor cannot access plaintext
    print("Auditor cannot decrypt content.")

# ==========================================
# MENUS & INTERFACE
# ==========================================

def user_menu(username: str, role: str):
    """
    Displays the menu for a logged-in user based on their role.
    Parameters:
      username: The logged-in user's name.
      role: The user's role identifier.
    Returns:
      None
    """
    # Display the user's role
    print(f"\nWelcome {username} ({ROLE_NAMES.get(role, role)})")
    while True:
        print("\n1. Perform Role Action")
        print("2. Logout")
        choice = input("Enter choice: ")
        
        # Route to the appropriate role action
        if choice == '1':
            if role == "Role1": role1_action(username)
            elif role == "Role2": role2_action()
            elif role == "Role3": role3_action()
        elif choice == '2':
            break
        else:
            print("Invalid choice")

def main():
    """
    Main entry point: Displays login menu and handles authentication.
    Parameters:
      None
    Returns:
      None
    """
    while True:
        print("\n--- Main Menu ---")
        print("1. Login")
        print("2. Exit")
        choice = input("Enter choice: ")
        
        if choice == '1':
            # Collect credentials
            user = input("Username: ")
            pwd = input("Password: ")
            
            # Authenticate user
            if user in USERS and USERS[user]["password"] == pwd:
                user_menu(user, USERS[user]["role"])
            else:
                print("Invalid credentials.")
        elif choice == '2':
            break

# Ensure the script runs when executed directly
if __name__ == "__main__":
    main()
