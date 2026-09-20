"""
============================================================
HealthSecure System
============================================================
Purpose:
A role-based medical records management system demonstrating
secure storage, retrieval, and access control of patient data.

Algorithms used & Why:
- RSA Encryption (PKCS1_OAEP): For encrypting the patient data securely. RSA is used here to securely encrypt data meant for a specific user.
- RSA Digital Signature (PKCS1_v1_5): To sign the hash of the data, ensuring authenticity and non-repudiation.
- SHA-256 Hashing: For generating a fixed-size digest of the encrypted data to check data integrity.

Roles & Access:
- Doctor: Can add, view, and decrypt their own records (has private key).
- Nurse: Can view encrypted records and verify signatures (has public key, but no private key to decrypt).
- Admin: Can view metadata and verify signatures (has public key, no private key).

How to run:
Run `python q1_healthsecure.py`. 
Login with 'doctor1'/'123', 'nurse1'/'123', or 'admin1'/'123'.
"""

# ============================================================
# SECTION: IMPORTS & SETTINGS — Required modules and constants
# ============================================================
import hashlib, pickle, json, os  # Standard libraries for hashing, serialization, data format, and OS ops
from datetime import datetime  # For timestamps
from Crypto.Cipher import PKCS1_OAEP  # RSA encryption scheme
from Crypto.Hash import SHA256  # SHA-256 hash algorithm
from Crypto.PublicKey import RSA  # RSA key generation
from Crypto.Signature import pkcs1_15  # RSA signature scheme

# ==== USER ACCOUNTS ====
# Dictionary storing username: (password, role)
USERS = {"doctor1": ("123", "doctor"), "nurse1": ("123", "nurse"), "admin1": ("123", "admin")}
# Dictionary mapping role codes to display names
ROLE_NAMES = {"doctor": "Doctor", "nurse": "Nurse", "admin": "Admin"}

# ==== FIXED SETTINGS ====
DATA_FILE = "healthsecure_records.pkl"  # File to persist records
RECORDS = []  # In-memory list of records
USER_KEYS = {} # Stores private keys for demo purposes in memory

# ============================================================
# SECTION: CRYPTO FUNCTIONS — Hashing, Keys, Encryption, Signatures
# ============================================================

# Computes the SHA-256 hash of the provided data.
# Converts data to bytes if needed.
# Parameters: data (str or bytes)
# Returns: hex string of the hash
def hash_data(data):
    """Compute SHA-256 hash of data using hashlib."""
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()  # Compute and return hex digest

# Generates a 2048-bit RSA key pair for secure encryption and signing.
# Parameters: None
# Returns: tuple (public_key, private_key)
def generate_keys():
    """Generates 2048-bit RSA keys."""
    key = RSA.generate(2048)  # Generate RSA key object
    return key.publickey(), key  # Return pub and priv keys

# Retrieves or generates RSA keys for a specific user.
# Parameters: username (str)
# Returns: tuple (public_key, private_key)
def get_user_keys(username):
    """Gets or generates keys for a user."""
    if username not in USER_KEYS:  # If user doesn't have keys yet
        pub, priv = generate_keys()  # Generate new keys
        USER_KEYS[username] = (pub, priv)  # Store them in the dictionary
    return USER_KEYS[username]  # Return the user's keys

# Encrypts data using RSA PKCS1_OAEP scheme with the provided public key.
# Parameters: data (str or bytes), public_key (RSA key object)
# Returns: encrypted bytes
def encrypt_data(data, public_key):
    """Encrypts data using PKCS1_OAEP."""
    if isinstance(data, str):
        data = data.encode()  # Convert to bytes
    cipher_rsa = PKCS1_OAEP.new(public_key)  # Create cipher object with public key
    return cipher_rsa.encrypt(data)  # Encrypt and return

# Decrypts ciphertext using RSA PKCS1_OAEP scheme with the provided private key.
# Parameters: enc_data (bytes), private_key (RSA key object)
# Returns: decrypted string
def decrypt_data(enc_data, private_key):
    """Decrypts data using PKCS1_OAEP."""
    cipher_rsa = PKCS1_OAEP.new(private_key)  # Create cipher object with private key
    return cipher_rsa.decrypt(enc_data).decode()  # Decrypt and decode to string

# Signs the provided data (or its hash) using RSA PKCS1_v1_5 with the private key.
# Parameters: data (str or bytes), private_key (RSA key object)
# Returns: signature bytes
def sign_data(data, private_key):
    """Signs data (hash string) using PKCS1_v1_5."""
    if isinstance(data, str):
        data = data.encode()  # Convert to bytes
    hash_obj = SHA256.new(data)  # Create hash object
    return pkcs1_15.new(private_key).sign(hash_obj)  # Sign the hash and return

# Verifies an RSA PKCS1_v1_5 signature using the public key.
# Parameters: data (str or bytes), sig (bytes), pub (RSA key object)
# Returns: boolean indicating valid or not
def verify_signature(data, sig, pub):
    """Verifies PKCS1_v1_5 signature."""
    if isinstance(data, str):
        data = data.encode()  # Convert to bytes
    hash_obj = SHA256.new(data)  # Recreate hash object
    try:
        pkcs1_15.new(pub).verify(hash_obj, sig)  # Attempt verification
        return True  # Signature is valid
    except (ValueError, TypeError):
        return False  # Signature is invalid

# ============================================================
# SECTION: STORAGE HELPERS — Loading and saving records
# ============================================================

# Loads patient records from the pickle file into memory.
# Parameters: None
# Returns: None
def load_records():
    """Loads records from pickle file."""
    global RECORDS
    if os.path.exists(DATA_FILE):  # Check if file exists
        with open(DATA_FILE, "rb") as f:  # Open in read-binary mode
            RECORDS = pickle.load(f)  # Deserialize records

# Saves patient records from memory to the pickle file.
# Parameters: None
# Returns: None
def save_records():
    """Saves records to pickle file."""
    with open(DATA_FILE, "wb") as f:  # Open in write-binary mode
        pickle.dump(RECORDS, f)  # Serialize and save records

# ============================================================
# SECTION: ROLE ACTIONS — Specific functions for Doctor, Nurse, Admin
# ============================================================

# Doctor action: Adds a new patient record securely.
# Parameters: username (str)
# Returns: None
def doctor_action_add(username):
    print("\n--- Enter Patient Info ---")
    # Step 1: Gather patient information
    name = input("Name: ")  # Get name
    age = input("Age: ")  # Get age
    gender = input("Gender: ")  # Get gender
    blood = input("Blood Group: ")  # Get blood group
    diag = input("Diagnosis: ")  # Get diagnosis
    
    # Step 2: Serialize patient info into a JSON string
    patient_info = json.dumps({"name": name, "age": age, "gender": gender, "blood": blood, "diagnosis": diag})
    
    # Step 3: Retrieve doctor's keys
    pub_key, priv_key = get_user_keys(username)
    
    # Step 4: Encrypt data using doctor's public key (Only doctor can decrypt later)
    enc_data = encrypt_data(patient_info, pub_key)
    # Step 5: Hash the encrypted data for integrity
    data_hash = hash_data(enc_data)
    # Step 6: Sign the hash with doctor's private key for authenticity
    signature = sign_data(data_hash, priv_key)
    
    # Step 7: Create record object
    record_id = len(RECORDS) + 1  # Generate new ID
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Current time
    
    record = {
        "id": record_id,
        "owner": username,
        "enc_data": enc_data,
        "hash": data_hash,
        "signature": signature,
        "pub_key": pub_key.export_key(),  # Export public key for others to verify
        "timestamp": timestamp
    }
    # Step 8: Append to list and save
    RECORDS.append(record)
    save_records()
    print(f"Record {record_id} saved successfully.")

# Doctor action: View a list of their own records.
# Parameters: username (str)
# Returns: None
def doctor_action_view(username):
    print("\n--- View Records ---")
    # Filter records to only show those owned by this doctor
    my_records = [r for r in RECORDS if r["owner"] == username]
    if not my_records:
        print("No records found.")
        return
    for r in my_records:
        # Print record metadata (not decrypted yet)
        print(f"ID: {r['id']} | Hash: {r['hash'][:10]}... | Time: {r['timestamp']}")
        
# Doctor action: Decrypt and read a patient record.
# Parameters: username (str)
# Returns: None
def doctor_action_decrypt(username):
    print("\n--- Decrypt Record ---")
    try:
        # Step 1: Get Record ID
        rid = int(input("Enter Record ID: "))
        # Step 2: Find the record ensuring ownership
        record = next((r for r in RECORDS if r["id"] == rid and r["owner"] == username), None)
        if not record:
            print("Record not found or access denied.")
            return
            
        # Step 3: Get doctor's private key for decryption
        pub_key, priv_key = get_user_keys(username)
        
        # INTEGRITY CHECK: Recompute SHA-256 hash of encrypted data
        # and compare with the stored hash to detect tampering
        current_hash = hash_data(record["enc_data"])
        if current_hash != record["hash"]:
            print("ERROR: Hash integrity verification failed!")
            return
            
        # AUTHENTICITY CHECK: Verify RSA digital signature using 
        # the doctor's public key to confirm the data was signed by them
        loaded_pub_key = RSA.import_key(record["pub_key"])  # Load stored public key
        if not verify_signature(record["hash"], record["signature"], loaded_pub_key):
            print("ERROR: Digital signature verification failed!")
            return
            
        # SECURITY: Only decrypt if BOTH integrity and authenticity checks pass
        print("Integrity and signature verified. Decrypting...")
        # Step 4: Decrypt the data using doctor's private key
        dec_data = decrypt_data(record["enc_data"], priv_key)
        # Step 5: Parse and print the JSON data
        print("Decrypted Info:", json.loads(dec_data))
        
    except ValueError:
        print("Invalid input.")

# Nurse action: View list of all records (encrypted).
# Parameters: None
# Returns: None
def nurse_action_view():
    print("\n--- Nurse: View Records ---")
    if not RECORDS:
        print("No records.")
        return
    for r in RECORDS:
        # Nurse can see metadata but NOT decrypt data
        # NURSE CANNOT DECRYPT: Nurse role does not have access to the
        # doctor's private key, so decryption is not possible.
        print(f"ID: {r['id']} | Owner: {r['owner']} | Enc: {r['enc_data'].hex()[:10]}... | Hash: {r['hash'][:10]}... | Sig: {r['signature'].hex()[:10]}... | Time: {r['timestamp']}")

# Nurse action: Verify the integrity and authenticity of a record.
# Parameters: None
# Returns: None
def nurse_action_verify():
    print("\n--- Nurse: Verify Record ---")
    try:
        rid = int(input("Enter Record ID to verify: "))
        # Find record by ID
        record = next((r for r in RECORDS if r["id"] == rid), None)
        if not record:
            print("Record not found.")
            return
            
        # Step 1: Verify Integrity
        # Recompute hash and compare
        current_hash = hash_data(record["enc_data"])
        if current_hash == record["hash"]:
            print("Integrity check: PASS")  # Hashes match
        else:
            print("Integrity check: FAIL")  # Hashes differ
            return
            
        # Step 2: Verify Authenticity
        # Nurse CAN verify integrity and authenticity using the public key.
        loaded_pub_key = RSA.import_key(record["pub_key"])  # Load doctor's public key
        if verify_signature(record["hash"], record["signature"], loaded_pub_key):
            print("Signature check: PASS")  # Signature matches
        else:
            print("Signature check: FAIL")  # Signature invalid
            
    except ValueError:
        print("Invalid input.")

# Admin action: View metadata of all records.
# Parameters: None
# Returns: None
def admin_action_view():
    print("\n--- Admin: View Metadata ---")
    if not RECORDS:
        print("No records.")
        return
    for r in RECORDS:
        # Admin sees minimal metadata for auditing
        # ADMIN CANNOT DECRYPT: Admin lacks the private key.
        print(f"ID: {r['id']} | Owner: {r['owner']} | Hash: {r['hash'][:10]}... | Time: {r['timestamp']}")

# Admin action: Verify the digital signature of a record.
# Parameters: None
# Returns: None
def admin_action_verify():
    print("\n--- Admin: Verify Signature ---")
    try:
        rid = int(input("Enter Record ID to verify: "))
        # Find record
        record = next((r for r in RECORDS if r["id"] == rid), None)
        if not record:
            print("Record not found.")
            return
            
        # Step 1: Verify Authenticity using public key
        loaded_pub_key = RSA.import_key(record["pub_key"])
        if verify_signature(record["hash"], record["signature"], loaded_pub_key):
            print("Signature check: PASS")
        else:
            print("Signature check: FAIL")
    except ValueError:
        print("Invalid input.")

# ============================================================
# SECTION: MENUS — User interaction and navigation
# ============================================================

# Displays the correct menu based on the user's role.
# Parameters: username (str), role (str)
# Returns: None
def user_menu(username, role):
    while True:
        print(f"\nWelcome {username} ({ROLE_NAMES[role]})")
        
        # Menu option 1: Doctor options
        if role == "doctor":
            print("1. Add Patient Record")  # Create new record
            print("2. View My Records")     # List records
            print("3. Decrypt My Record")   # Read a record
            print("4. Logout")              # Exit menu
            choice = input("Choice: ")
            if choice == "1": doctor_action_add(username)
            elif choice == "2": doctor_action_view(username)
            elif choice == "3": doctor_action_decrypt(username)
            elif choice == "4": break
            
        # Menu option 2: Nurse options
        elif role == "nurse":
            print("1. View Records")      # List all records metadata
            print("2. Verify Record")     # Check integrity/authenticity
            print("3. Logout")            # Exit menu
            choice = input("Choice: ")
            if choice == "1": nurse_action_view()
            elif choice == "2": nurse_action_verify()
            elif choice == "3": break
            
        # Menu option 3: Admin options
        elif role == "admin":
            print("1. View Metadata")     # List basic metadata
            print("2. Verify Signature")  # Check authenticity only
            print("3. Logout")            # Exit menu
            choice = input("Choice: ")
            if choice == "1": admin_action_view()
            elif choice == "2": admin_action_verify()
            elif choice == "3": break

# Main entry point. Handles login loop.
# Parameters: None
# Returns: None
def main():
    load_records()  # Load existing records from file
    while True:
        print("\n=== HealthSecure System ===")
        # Get login credentials
        uname = input("Username (or 'exit'): ")
        if uname.lower() == 'exit':
            break  # Exit program
        pwd = input("Password: ")
        
        # Authenticate user
        if uname in USERS and USERS[uname][0] == pwd:
            user_menu(uname, USERS[uname][1])  # Route to correct menu
        else:
            print("Invalid credentials.")  # Login failed

if __name__ == "__main__":
    main()
