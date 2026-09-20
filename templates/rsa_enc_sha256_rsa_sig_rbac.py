"""
==============================================================================
Role-Based Crypto System Template (RSA + SHA256 + RSA Signature)
Purpose: Ready-to-run template for exam questions involving RBAC and RSA.

Algorithms Used:
- RSA (PKCS1_OAEP): For data encryption.
- SHA-256: For data hashing.
- RSA Signature (pkcs1_15): For digital signatures.

Roles:
- Uploader: Can encrypt and sign data.
- Reviewer: Can verify signatures and decrypt data.
- Auditor: Can only verify signatures (no decryption).

How to Run:
Run the script directly. 
Sample credentials: 
- Uploader: username 'user1', password '123'
- Reviewer: username 'user2', password '123'
- Auditor: username 'user3', password '123'
==============================================================================
"""

import os
import pickle
import hashlib
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

# ============================================================
# SECTION 1 — SETTINGS & DATA SETUP
# ============================================================

# CUSTOMIZE: Change filename if needed
DB_FILE = "data_store.pkl"

# CUSTOMIZE: Role names for the UI
ROLE_NAMES = {
    1: "Uploader",
    2: "Reviewer",
    3: "Auditor"
}

# CUSTOMIZE: Add or remove users, change passwords and roles
USERS = {
    "user1": {"password": "123", "role": 1},
    "user2": {"password": "123", "role": 2},
    "user3": {"password": "123", "role": 3},
}

# Global dictionary for user RSA keys (for simplicity in educational template)
# In real scenarios, keys are securely managed.
USER_KEYS = {}

# Generate RSA keys for users
for uname in USERS:
    USER_KEYS[uname] = RSA.generate(2048)  # Generate 2048-bit RSA key pair

# ============================================================
# SECTION 2 — CRYPTO FUNCTIONS
# ============================================================

def rsa_encrypt(data_bytes, public_key):
    """
    Encrypts data using RSA with PKCS1_OAEP padding.
    Parameters: data_bytes (bytes), public_key (RSA key object)
    Returns: bytes (ciphertext)
    """
    # CUSTOMIZE: RSA Encryption using PKCS1_OAEP
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data_bytes)

def rsa_decrypt(cipher_bytes, private_key):
    """
    Decrypts data using RSA with PKCS1_OAEP padding.
    Parameters: cipher_bytes (bytes), private_key (RSA key object)
    Returns: bytes (plaintext)
    """
    # CUSTOMIZE: RSA Decryption using PKCS1_OAEP
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(cipher_bytes)

def sha256_hash(data_bytes):
    """
    Computes the SHA-256 hash of the given data.
    Parameters: data_bytes (bytes)
    Returns: bytes (hash digest)
    """
    # CUSTOMIZE: SHA-256 hashing
    return hashlib.sha256(data_bytes).digest()

def rsa_sign(data_bytes, private_key):
    """
    Generates an RSA digital signature using pkcs1_15.
    Parameters: data_bytes (bytes), private_key (RSA key object)
    Returns: bytes (signature)
    """
    # CUSTOMIZE: RSA Signature using pkcs1_15
    h = SHA256.new(data_bytes)
    return pkcs1_15.new(private_key).sign(h)

def rsa_verify(data_bytes, signature, public_key):
    """
    Verifies an RSA digital signature.
    Parameters: data_bytes (bytes), signature (bytes), public_key (RSA key object)
    Returns: bool (True if valid, False otherwise)
    """
    # CUSTOMIZE: RSA Signature verification
    h = SHA256.new(data_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ============================================================
# SECTION 3 — STORAGE HELPERS
# ============================================================

def load_data():
    """
    Loads persistent data from file.
    Parameters: none
    Returns: list (records)
    """
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'rb') as f:
            return pickle.load(f)
    return []

def save_data(data):
    """
    Saves records to persistent file.
    Parameters: data (list)
    Returns: none
    """
    with open(DB_FILE, 'wb') as f:
        pickle.dump(data, f)
    print(f"\n[+] Data saved to {DB_FILE}")

def get_input_data():
    """
    Gets input data from keyboard or file.
    Parameters: none
    Returns: bytes (input data)
    """
    print("\n--- Enter Data ---")
    text = input("Enter text (or path to a file): ")
    if os.path.isfile(text):
        with open(text, 'rb') as f:
            return f.read()
    return text.encode()

def select_record(records):
    """
    Prompts user to select a record.
    Parameters: records (list)
    Returns: dict (selected record) or None
    """
    if not records:
        print("\n[-] No records found.")
        return None
    print("\n--- Available Records ---")
    for i, r in enumerate(records):
        print(f"[{i}] Owner: {r['owner']} | Time: {r['timestamp']}")
    try:
        idx = int(input("\nSelect record number: "))
        if 0 <= idx < len(records):
            return records[idx]
        print("[-] Invalid selection.")
    except ValueError:
        print("[-] Invalid input.")
    return None

# ============================================================
# SECTION 4 — ROLE ACTIONS
# ============================================================

def uploader_action(username):
    """
    Action for role 1 (Uploader). Encrypts and signs data.
    Parameters: username (str)
    Returns: none
    """
    # ACCESS CONTROL: Only Uploaders can add new records
    # CUSTOMIZE: Role 1 Action - Encrypt, Hash, Sign, Store
    # Step 1: Read data from user (keyboard or file)
    data_bytes = get_input_data()
    
    # We encrypt using the uploader's public key for this example
    pub_key = USER_KEYS[username].publickey()
    priv_key = USER_KEYS[username]
    
    # Step 2: Encrypt using RSA
    enc_data = rsa_encrypt(data_bytes, pub_key)
    
    # Step 3: Compute SHA-256 hash of ciphertext
    # Hash the encrypted data
    data_hash = sha256_hash(enc_data)
    
    # Step 4: Sign the encrypted data using RSA
    # Sign the encrypted data
    signature = rsa_sign(enc_data, priv_key)
    
    # Step 5: Store encrypted data, hash, signature, timestamp
    record = {
        "owner": username,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "enc_data": enc_data,
        "hash": data_hash,
        "signature": signature
    }
    
    records = load_data()
    records.append(record)
    save_data(records)
    print("[+] Record uploaded successfully.")

def reviewer_action(username):
    """
    Action for role 2 (Reviewer). Verifies and decrypts data.
    Parameters: username (str)
    Returns: none
    """
    # ACCESS CONTROL: Reviewers can decrypt, but MUST verify first
    # CUSTOMIZE: Role 2 Action - Verify and Decrypt
    records = load_data()
    record = select_record(records)
    if not record:
        return
    
    owner = record['owner']
    enc_data = record['enc_data']
    stored_hash = record['hash']
    signature = record['signature']
    
    owner_pub_key = USER_KEYS[owner].publickey()
    owner_priv_key = USER_KEYS[owner]
    
    # INTEGRITY CHECK: Recompute hash and compare with stored hash
    # Verify hash integrity
    calc_hash = sha256_hash(enc_data)
    hash_valid = (calc_hash == stored_hash)
    
    # AUTHENTICITY CHECK: Verify digital signature using public key
    # Verify signature
    sig_valid = rsa_verify(enc_data, signature, owner_pub_key)
    
    print("\n--- Verification ---")
    print(f"Hash Integrity: {'PASS' if hash_valid else 'FAIL'}")
    print(f"Digital Signature: {'PASS' if sig_valid else 'FAIL'}")
    
    # SECURITY: Only decrypt if BOTH checks pass (CIA triad)
    # CRITICAL: Verify BEFORE decrypt. Only decrypt if both integrity + signature pass.
    if hash_valid and sig_valid:
        print("\n[+] Verification passed. Decrypting data...")
        dec_data = rsa_decrypt(enc_data, owner_priv_key)
        print(f"Decrypted Data: {dec_data.decode(errors='replace')}")
    else:
        print("\n[-] Verification failed. Decryption aborted.")

def auditor_action(username):
    """
    Action for role 3 (Auditor). Verifies signatures and hashes only.
    Parameters: username (str)
    Returns: none
    """
    # ACCESS CONTROL: Auditors cannot decrypt data
    # CUSTOMIZE: Role 3 Action - View metadata and verify signature
    records = load_data()
    record = select_record(records)
    if not record:
        return
        
    owner = record['owner']
    enc_data = record['enc_data']
    signature = record['signature']
    owner_pub_key = USER_KEYS[owner].publickey()
    
    print("\n--- Metadata ---")
    print(f"Owner: {owner}")
    print(f"Timestamp: {record['timestamp']}")
    print(f"Stored Hash: {record['hash'].hex()}")
    
    # AUTHENTICITY CHECK: Verify digital signature using public key
    sig_valid = rsa_verify(enc_data, signature, owner_pub_key)
    print(f"\nSignature Verification: {'PASS' if sig_valid else 'FAIL'}")
    print("[-] Auditor cannot decrypt data.")

def view_my_records(username):
    """
    Shows a user's own records.
    Parameters: username (str)
    Returns: none
    """
    records = load_data()
    my_records = [r for r in records if r['owner'] == username]
    if not my_records:
        print("\n[-] You have no records.")
        return
    print("\n--- My Records ---")
    for r in my_records:
        print(f"Time: {r['timestamp']} | Hash: {r['hash'].hex()}")

# ============================================================
# SECTION 5 — MENUS
# ============================================================

def user_menu(username, role):
    """
    Displays the menu based on the user's role.
    Parameters: username (str), role (int)
    Returns: none
    """
    while True:
        print(f"\n=== {ROLE_NAMES[role]} Menu ({username}) ===")
        if role == 1:
            print("1. Upload New Record (Encrypt + Sign)")
            print("2. View My Records")
        elif role == 2:
            print("1. Review Record (Verify + Decrypt)")
        elif role == 3:
            print("1. Audit Record (Verify Signature Only)")
            
        print("0. Logout")
        
        choice = input("Choice: ")
        if choice == '0':
            break
            
        if role == 1:
            if choice == '1': uploader_action(username)
            elif choice == '2': view_my_records(username)
        elif role == 2:
            if choice == '1': reviewer_action(username)
        elif role == 3:
            if choice == '1': auditor_action(username)

def main():
    """
    Main entry point. Authenticates users and routes to correct menus.
    Parameters: none
    Returns: none
    """
    while True:
        print("\n=== Secure System Login ===")
        uname = input("Username (or 'q' to quit): ")
        if uname.lower() == 'q': break
        
        if uname in USERS:
            pwd = input("Password: ")
            if USERS[uname]["password"] == pwd:
                user_menu(uname, USERS[uname]["role"])
            else:
                print("[-] Invalid password.")
        else:
            print("[-] Unknown user.")

if __name__ == "__main__":
    main()
