"""
==============================================================================
SecureVault - Secure Record Management System
Purpose: Manage confidential records with encryption, integrity, and authenticity.

Algorithms Used:
- DES-CBC: For data encryption (chosen for legacy support or exam requirement).
- SHA-256: For hashing to ensure data integrity.
- ElGamal Digital Signature (Raw Math): To provide data authenticity and non-repudiation.

Roles:
- Client: Can upload (encrypt and sign) new records.
- Lawyer: Can review (verify and decrypt) existing records.
- Compliance Officer: Can audit (verify signatures and hashes) without decrypting.

How to Run:
Run the script directly. 
Sample credentials: 
- Client: username 'client1', password '123'
- Lawyer: username 'lawyer1', password '123'
- Compliance: username 'compliance1', password '123'
==============================================================================
"""

import hashlib
import pickle
import datetime
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# ============================================================
# SECTION 1 — SETTINGS & DATA SETUP
# ============================================================

USERS = {"client1": ("123", "client"), "lawyer1": ("123", "lawyer"), "compliance1": ("123", "compliance")}
ROLE_NAMES = {"client": "Client", "lawyer": "Lawyer", "compliance": "Compliance Officer"}
DATA_FILE = "securevault_records.pkl"

RECORDS = []

# ============================================================
# SECTION 2 — CRYPTO FUNCTIONS
# ============================================================

def encrypt_data(data, key, iv):
    """
    Encrypts data using DES in CBC mode.
    Parameters: data (str), key (str), iv (str)
    Returns: bytes (ciphertext)
    """
    # Create DES cipher in CBC mode with the key and IV
    cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv.encode('utf-8'))
    # Pad data to 8-byte blocks and encrypt
    return cipher.encrypt(pad(data.encode('utf-8'), DES.block_size))

def decrypt_data(ciphertext, key, iv):
    """
    Decrypts DES-CBC ciphertext back to string.
    Parameters: ciphertext (bytes), key (str), iv (str)
    Returns: str (plaintext) or None if decryption fails
    """
    try:
        # Recreate DES cipher for decryption
        cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv.encode('utf-8'))
        # Decrypt and unpad to recover original data
        return unpad(cipher.decrypt(ciphertext), DES.block_size).decode('utf-8')
    except ValueError:
        # Return None if unpadding fails (e.g. wrong key/IV)
        return None

def hash_data(data):
    """
    Computes the SHA-256 hash of the given data.
    Parameters: data (bytes)
    Returns: str (hexadecimal hash digest)
    """
    # Create SHA-256 hash object and return hex digest
    return hashlib.sha256(data).hexdigest()

def gcd(a, b):
    """
    Computes the Greatest Common Divisor using Euclidean algorithm.
    Parameters: a (int), b (int)
    Returns: int (gcd of a and b)
    """
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """
    Computes the Modular Inverse using Extended Euclidean algorithm.
    Parameters: a (int), m (int)
    Returns: int (modular inverse of a modulo m)
    """
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    return x

def sign_data(data, p, g, x):
    """
    Signs data using raw ElGamal digital signature.
    Parameters: data (bytes), p (prime), g (generator), x (private key)
    Returns: tuple (r, s)
    """
    # ElGamal Signature Generation:
    # h = SHA-256 hash of the data, converted to integer
    h = int(hashlib.sha256(data).hexdigest(), 16)
    k = 2
    # Find random k such that gcd(k, p-1) = 1 (k must be coprime to p-1)
    while gcd(k, p - 1) != 1:
        k += 1
    # r = g^k mod p (first part of signature)
    r = pow(g, k, p)
    # k_inv = modular inverse of k modulo (p-1)
    k_inv = mod_inverse(k, p - 1)
    # s = (h - x*r) * k_inv mod (p-1) (second part of signature)
    s = ((h - x * r) * k_inv) % (p - 1)
    return r, s

def verify_signature(data, r, s, p, g, y):
    """
    Verifies raw ElGamal digital signature.
    Parameters: data (bytes), r (int), s (int), p (prime), g (generator), y (public key)
    Returns: bool (True if valid, False otherwise)
    """
    # ElGamal Signature Verification:
    # Compute integer hash of the data
    h = int(hashlib.sha256(data).hexdigest(), 16)
    # Ensure r is in valid range
    if r < 1 or r >= p:
        return False
    # Compute v1 = g^h mod p
    v1 = pow(g, h, p)
    # Compute v2 = (y^r * r^s) mod p
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    # If v1 == v2, signature is VALID (proves data was signed by private key holder)
    return v1 == v2

# ============================================================
# SECTION 3 — STORAGE HELPERS
# ============================================================

def load_records():
    """
    Loads records from the persistent pickle file into memory.
    Parameters: none
    Returns: none (updates global RECORDS)
    """
    global RECORDS
    try:
        # Open file in read-binary mode
        with open(DATA_FILE, 'rb') as f:
            RECORDS = pickle.load(f)
    except FileNotFoundError:
        # If file doesn't exist, initialize empty list
        RECORDS = []

def save_records():
    """
    Saves the in-memory records to the persistent pickle file.
    Parameters: none
    Returns: none
    """
    # Open file in write-binary mode
    with open(DATA_FILE, 'wb') as f:
        pickle.dump(RECORDS, f)

def get_input_data():
    """
    Prompts user to provide input data via keyboard or file.
    Parameters: none
    Returns: tuple (source_type, data_string)
    """
    choice = input("Enter from (1) Keyboard or (2) File: ")
    if choice == '1':
        return "keyboard_input", input("Enter confidential record: ")
    elif choice == '2':
        filename = input("Enter filename: ")
        try:
            with open(filename, 'r') as f:
                return filename, f.read()
        except FileNotFoundError:
            print("File not found.")
            return None, None
    print("Invalid choice.")
    return None, None

def select_record():
    """
    Prompts user to select a specific record from the list.
    Parameters: none
    Returns: dict (the selected record) or None
    """
    if not RECORDS:
        print("No records available.")
        return None
    # List all available records with minimal metadata
    for i, rec in enumerate(RECORDS):
        print(f"[{i}] Owner: {rec['owner']}, Source: {rec['source']}, Timestamp: {rec['timestamp']}")
    try:
        idx = int(input("Select record index: "))
        if 0 <= idx < len(RECORDS):
            return RECORDS[idx]
        print("Invalid index.")
    except ValueError:
        print("Invalid input.")
    return None

# ============================================================
# SECTION 4 — ROLE ACTIONS
# ============================================================

def client_menu(username):
    """
    Provides the Client menu. Clients can add (encrypt and sign) records.
    Parameters: username (str)
    Returns: none
    """
    # ACCESS CONTROL: Only clients can encrypt and sign new data
    while True:
        print("\n--- Client Menu ---")
        print("1. Add new record")
        print("2. Logout")
        choice = input("Choice: ")
        
        if choice == '1':
            # Step 1: Read data from user (keyboard or file)
            source, data = get_input_data()
            if data:
                key = input("Enter DES key (8 chars): ")
                iv = input("Enter DES IV (8 chars): ")
                if len(key) != 8 or len(iv) != 8:
                    print("Key and IV must be exactly 8 chars.")
                    continue
                
                # Step 2: Encrypt using DES-CBC
                encrypted_data = encrypt_data(data, key, iv)
                # Step 3: Compute SHA-256 hash of ciphertext
                data_hash = hash_data(encrypted_data)
                
                try:
                    p = int(input("Enter prime p (e.g. 467): "))
                    g = int(input("Enter generator g (e.g. 2): "))
                    x = int(input("Enter private key x: "))
                except ValueError:
                    print("Invalid numbers.")
                    continue
                
                # Calculate public key y
                y = pow(g, x, p)
                # Step 4: Sign the hash using ElGamal digital signature
                r, s = sign_data(encrypted_data, p, g, x)
                timestamp = str(datetime.datetime.now())
                
                print(f"Ciphertext (Hex): {encrypted_data.hex()}")
                print(f"IV: {iv}")
                print(f"Hash: {data_hash}")
                print(f"Signature: (r={r}, s={s})")
                print(f"Timestamp: {timestamp}")
                
                # Step 5: Store encrypted data, hash, signature, timestamp
                record = {
                    'owner': username,
                    'source': source,
                    'encrypted_data': encrypted_data,
                    'hash': data_hash,
                    'signature': (r, s),
                    'iv': iv,
                    'public_key': (p, g, y),
                    'timestamp': timestamp,
                    'verification_status': 'Pending'
                }
                RECORDS.append(record)
                save_records()
                print("Record saved.")
                
        elif choice == '2':
            break
        else:
            print("Invalid choice.")

def lawyer_menu(username):
    """
    Provides the Lawyer menu. Lawyers can verify and decrypt records.
    Parameters: username (str)
    Returns: none
    """
    # ACCESS CONTROL: Lawyers have decryption capabilities but must verify first
    while True:
        print("\n--- Lawyer Menu ---")
        print("1. View and Decrypt Record")
        print("2. Logout")
        choice = input("Choice: ")
        
        if choice == '1':
            # Step 1: Select record to review
            record = select_record()
            if record:
                # INTEGRITY CHECK: Recompute hash and compare with stored hash
                computed_hash = hash_data(record['encrypted_data'])
                integrity_pass = (computed_hash == record['hash'])
                
                # AUTHENTICITY CHECK: Verify digital signature using public key
                p, g, y = record['public_key']
                r, s = record['signature']
                authenticity_pass = verify_signature(record['encrypted_data'], r, s, p, g, y)
                
                # SECURITY: Only decrypt if BOTH checks pass (CIA triad)
                if integrity_pass and authenticity_pass:
                    print("Integrity and Authenticity checks passed.")
                    record['verification_status'] = f"Verified by Lawyer at {datetime.datetime.now()}"
                    save_records()
                    
                    key = input("Enter DES key: ")
                    iv = input("Enter DES IV: ")
                    # Step 2: Decrypt the record
                    plaintext = decrypt_data(record['encrypted_data'], key, iv)
                    if plaintext:
                        print(f"\n--- Decrypted Record --- \n{plaintext}")
                    else:
                        print("Decryption failed. Incorrect key/IV.")
                else:
                    print("ERROR: Integrity or Authenticity check failed. Decryption aborted.")
                    record['verification_status'] = f"Failed Verification at {datetime.datetime.now()}"
                    save_records()
        elif choice == '2':
            break
        else:
            print("Invalid choice.")

def compliance_menu(username):
    """
    Provides the Compliance menu. Compliance can audit (verify) but not decrypt.
    Parameters: username (str)
    Returns: none
    """
    # ACCESS CONTROL: Compliance officer cannot decrypt, only checks metadata and signatures
    while True:
        print("\n--- Compliance Menu ---")
        print("1. Generate Compliance Report")
        print("2. Logout")
        choice = input("Choice: ")
        
        if choice == '1':
            if not RECORDS:
                print("No records available.")
            else:
                print("\n--- Compliance Report ---")
                print(f"Generated at: {datetime.datetime.now()}")
                for r_idx, r in enumerate(RECORDS):
                    print(f"\nRecord [{r_idx}] Owner: {r['owner']}, Source: {r['source']}")
                    
                    # INTEGRITY CHECK: Recompute hash and compare with stored hash
                    computed_hash = hash_data(r['encrypted_data'])
                    integrity_pass = (computed_hash == r['hash'])
                    
                    # AUTHENTICITY CHECK: Verify digital signature using public key
                    p, g, y = r['public_key']
                    sig_r, sig_s = r['signature']
                    authenticity_pass = verify_signature(r['encrypted_data'], sig_r, sig_s, p, g, y)
                    
                    print(f"Hash Valid: {'Yes' if integrity_pass else 'No'}")
                    print(f"Signature Valid: {'Yes' if authenticity_pass else 'No'}")
                    print(f"Last Status: {r['verification_status']}")
                    print(f"Timestamp: {r['timestamp']}")
                    
        elif choice == '2':
            break
        else:
            print("Invalid choice.")

def main():
    """
    Main entry point. Authenticates users and routes to correct menus.
    Parameters: none
    Returns: none
    """
    load_records()
    while True:
        print("\n--- SecureVault System ---")
        username = input("Username: ")
        password = input("Password: ")
        
        # Verify credentials
        if username in USERS and USERS[username][0] == password:
            role = USERS[username][1]
            print(f"Login successful. Welcome {ROLE_NAMES[role]}.")
            
            # Route to correct menu based on role
            if role == "client":
                client_menu(username)
            elif role == "lawyer":
                lawyer_menu(username)
            elif role == "compliance":
                compliance_menu(username)
        else:
            print("Invalid credentials. Try again.")

if __name__ == "__main__":
    main()
