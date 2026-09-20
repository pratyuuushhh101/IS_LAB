"""
============================================================
MediSecure System
============================================================
Purpose:
A secure patient-record management system to upload, store, 
and verify medical documents utilizing a combination of symmetric 
encryption and digital signatures.

Algorithms used & Why:
- AES-CBC: For symmetric encryption of patient documents, providing confidentiality.
- SHA-256: Used to hash the encrypted document, creating a fixed-size digest for integrity.
- RSA Digital Signature (PKCS1_15): Used by the patient to sign the document hash, ensuring authenticity and non-repudiation.

Roles & Access:
- Patient: Can encrypt and upload records, and sign them (holds private key).
- Doctor: Can view and decrypt records after successful verification (needs symmetric key from patient out-of-band).
- Auditor: Can view metadata and verify signatures (uses public key).

How to run:
Run `python q3_medisecure.py`.
Login with 'patient1'/'123', 'doctor1'/'123', or 'auditor1'/'123'.
"""

# ============================================================
# SECTION: IMPORTS & SETTINGS — Required modules and constants
# ============================================================
import hashlib  # Standard hashing library
import pickle  # For object serialization
import datetime  # For timestamps
import os  # Operating system interfaces
from Crypto.Cipher import AES  # AES symmetric encryption
from Crypto.Util.Padding import pad, unpad  # AES block padding
from Crypto.PublicKey import RSA  # RSA key management
from Crypto.Signature import pkcs1_15  # RSA PKCS#1 v1.5 signature scheme
from Crypto.Hash import SHA256  # SHA-256 hashing for signatures

# Dictionary mapping username to (password, role)
USERS = {"patient1": ("123", "patient"), "doctor1": ("123", "doctor"), "auditor1": ("123", "auditor")}
# Dictionary for pretty-printing roles
ROLE_NAMES = {"patient": "Patient", "doctor": "Doctor", "auditor": "Auditor"}
DATA_FILE = "medisecure_records.pkl"  # Persistence file

RECORDS = []  # In-memory storage for records

# ============================================================
# SECTION: CRYPTO FUNCTIONS — Encryption, Hashing, Signing
# ============================================================

# Encrypts data using AES in CBC mode.
# Parameters: data (str), key (str), iv (str)
# Returns: encrypted bytes
def encrypt_data(data, key, iv):
    """Encrypt data using AES-CBC."""
    # Create AES cipher using key and IV
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    # Pad data and encrypt
    return cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

# Decrypts AES-CBC encrypted data.
# Parameters: ciphertext (bytes), key (str), iv (str)
# Returns: decrypted string, or None if failed
def decrypt_data(ciphertext, key, iv):
    """Decrypt data using AES-CBC."""
    try:
        # Recreate AES cipher
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        # Decrypt, unpad, and decode
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    except ValueError:
        return None  # Unpadding failed (wrong key/IV or corrupted data)

# Computes SHA-256 hash of the given data.
# Parameters: data (bytes)
# Returns: hex string hash
def hash_data(data):
    """Compute SHA-256 hash."""
    return hashlib.sha256(data).hexdigest()  # Compute and return digest

# Signs a hexadecimal hash string using an RSA private key.
# Parameters: hash_hex (str), private_key (bytes)
# Returns: signature bytes
def sign_data(hash_hex, private_key):
    """Sign hash using RSA PKCS1_15."""
    key = RSA.import_key(private_key)  # Load the private key
    h = SHA256.new(hash_hex.encode('utf-8'))  # Create a hash object of the hash string
    signature = pkcs1_15.new(key).sign(h)  # Generate signature
    return signature

# Verifies an RSA signature using a public key.
# Parameters: hash_hex (str), signature (bytes), public_key (bytes)
# Returns: bool indicating validity
def verify_signature(hash_hex, signature, public_key):
    """Verify RSA signature using PKCS1_15."""
    key = RSA.import_key(public_key)  # Load the public key
    h = SHA256.new(hash_hex.encode('utf-8'))  # Recreate hash object
    try:
        pkcs1_15.new(key).verify(h, signature)  # Attempt verification
        return True  # Valid signature
    except (ValueError, TypeError):
        return False  # Invalid signature

# ============================================================
# SECTION: STORAGE HELPERS — Loading, saving, and selecting records
# ============================================================

# Load records from the pickle file into the global list.
# Parameters: None
# Returns: None
def load_records():
    """Load records from pickle file."""
    global RECORDS
    try:
        with open(DATA_FILE, 'rb') as f:
            RECORDS = pickle.load(f)  # Load data
    except FileNotFoundError:
        RECORDS = []  # Initialize empty if no file

# Save global records list to the pickle file.
# Parameters: None
# Returns: None
def save_records():
    """Save records to pickle file."""
    with open(DATA_FILE, 'wb') as f:
        pickle.dump(RECORDS, f)  # Dump data to file

# Reads text data from a file specified by the user.
# Parameters: None
# Returns: tuple (filename, data_string)
def get_input_data():
    """Helper to read data from a file."""
    filename = input("Enter filename to read record from (e.g., patient_data.txt): ")
    try:
        with open(filename, 'r') as f:  # Read the specified file
            data = f.read()
        return filename, data
    except FileNotFoundError:
        print("File not found.")
        return None, None

# Interactive prompt to select a record from the list.
# Parameters: None
# Returns: record dictionary or None
def select_record():
    """Helper to select a record."""
    if not RECORDS:
        print("No records available.")
        return None
    # List all records
    for i, rec in enumerate(RECORDS):
        print(f"[{i}] Owner: {rec['owner']}, File: {rec['filename']}, Timestamp: {rec['timestamp']}")
    try:
        idx = int(input("Select record index: "))  # Get index
        if 0 <= idx < len(RECORDS):
            return RECORDS[idx]  # Return selected record
        print("Invalid index.")
    except ValueError:
        print("Invalid input.")
    return None

# ============================================================
# SECTION: ROLE ACTIONS — Patient, Doctor, Auditor menus
# ============================================================

# Patient menu and functionality.
# Parameters: username (str)
# Returns: None
def patient_menu(username):
    """Patient actions."""
    while True:
        # Menu options
        print("\n--- Patient Menu ---")
        print("1. Upload new record")
        print("2. View own uploaded records")
        print("3. Logout")
        choice = input("Choice: ")
        
        if choice == '1':
            # Step 1: Get data to encrypt
            filename, data = get_input_data()
            if data:
                # Step 2: Get AES credentials
                key = input("Enter AES key (16 chars): ")
                iv = input("Enter AES IV (16 chars): ")
                if len(key) != 16 or len(iv) != 16:
                    print("Key and IV must be exactly 16 chars.")
                    continue
                
                # Step 3: Encrypt the data symmetrically
                encrypted_data = encrypt_data(data, key, iv)
                # Step 4: Compute hash of the ciphertext
                data_hash = hash_data(encrypted_data)
                
                # Step 5: Generate RSA keys for signing
                rsa_key = RSA.generate(2048)
                private_key = rsa_key.export_key()
                public_key = rsa_key.publickey().export_key()
                
                # Step 6: Digitally sign the hash using RSA private key
                signature = sign_data(data_hash, private_key)
                timestamp = str(datetime.datetime.now())
                
                # Step 7: Create and store the record
                record = {
                    'owner': username,
                    'filename': filename,
                    'encrypted_data': encrypted_data,
                    'hash': data_hash,
                    'signature': signature,
                    'iv': iv,
                    'public_key': public_key,
                    'timestamp': timestamp,
                    'verification_status': 'Pending'
                }
                RECORDS.append(record)
                save_records()
                print("Record uploaded successfully.")
        
        elif choice == '2':
            # View patient's own records
            own_records = [r for r in RECORDS if r['owner'] == username]
            if not own_records:
                print("No uploaded records found.")
            else:
                for r in own_records:
                    print(f"\nFilename: {r['filename']}")
                    print(f"Encrypted Data (Hex): {r['encrypted_data'].hex()}")
                    print(f"Hash: {r['hash']}")
                    print(f"Timestamp: {r['timestamp']}")
                    
        elif choice == '3':
            break  # Logout
        else:
            print("Invalid choice.")

# Doctor menu and functionality.
# Parameters: username (str)
# Returns: None
def doctor_menu(username):
    """Doctor actions."""
    while True:
        # Menu options
        print("\n--- Doctor Menu ---")
        print("1. View and Decrypt Record")
        print("2. Logout")
        choice = input("Choice: ")
        
        if choice == '1':
            record = select_record()
            if record:
                # INTEGRITY CHECK: Recompute SHA-256 hash of encrypted data
                # and compare with the stored hash to detect tampering
                computed_hash = hash_data(record['encrypted_data'])
                integrity_pass = (computed_hash == record['hash'])
                
                # AUTHENTICITY CHECK: Verify RSA digital signature using 
                # the patient's public key to confirm the data was signed by them
                authenticity_pass = verify_signature(record['hash'], record['signature'], record['public_key'])
                
                # SECURITY: Only decrypt if BOTH checks pass
                if integrity_pass and authenticity_pass:
                    print("Integrity and Authenticity checks passed.")
                    record['verification_status'] = f"Verified by Doctor at {datetime.datetime.now()}"
                    save_records()
                    
                    # Doctor needs the AES key (assumed shared out-of-band) to decrypt
                    key = input("Enter AES key: ")
                    iv = input("Enter AES IV: ")
                    plaintext = decrypt_data(record['encrypted_data'], key, iv)
                    if plaintext:
                        print(f"\n--- Decrypted Record --- \n{plaintext}")
                    else:
                        print("Decryption failed. Incorrect key/IV.")
                else:
                    # Verification failed
                    print("ERROR: Integrity or Authenticity check failed. Decryption aborted.")
                    record['verification_status'] = f"Failed Verification at {datetime.datetime.now()}"
                    save_records()
        elif choice == '2':
            break  # Logout
        else:
            print("Invalid choice.")

# Auditor menu and functionality.
# Parameters: username (str)
# Returns: None
def auditor_menu(username):
    """Auditor actions."""
    while True:
        # Menu options
        print("\n--- Auditor Menu ---")
        print("1. View Records and Verify Signatures")
        print("2. Logout")
        choice = input("Choice: ")
        
        if choice == '1':
            if not RECORDS:
                print("No records available.")
            else:
                for r in RECORDS:
                    # AUDITOR CANNOT DECRYPT: Auditor does not have the symmetric key
                    # Auditor CAN verify integrity and authenticity using the public key.
                    print(f"\nFilename: {r['filename']}")
                    print(f"Hash: {r['hash']}")
                    print(f"Timestamp: {r['timestamp']}")
                    authenticity_pass = verify_signature(r['hash'], r['signature'], r['public_key'])
                    if authenticity_pass:
                        print("Signature Valid: Yes")
                    else:
                        print("Signature Valid: No")
        elif choice == '2':
            break  # Logout
        else:
            print("Invalid choice.")

# Main entry point and authentication loop.
# Parameters: None
# Returns: None
def main():
    """Main menu and authentication."""
    load_records()
    while True:
        print("\n--- MediSecure System ---")
        username = input("Username: ")
        password = input("Password: ")
        
        # Authenticate and route to appropriate menu based on role
        if username in USERS and USERS[username][0] == password:
            role = USERS[username][1]
            print(f"Login successful. Welcome {ROLE_NAMES[role]}.")
            
            if role == "patient":
                patient_menu(username)
            elif role == "doctor":
                doctor_menu(username)
            elif role == "auditor":
                auditor_menu(username)
        else:
            print("Invalid credentials. Try again.")

if __name__ == "__main__":
    main()
