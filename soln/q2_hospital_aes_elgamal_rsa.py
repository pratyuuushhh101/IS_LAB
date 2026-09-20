"""
============================================================
Hospital Pipeline System
============================================================
Purpose:
Demonstrates a multi-layered cryptographic pipeline for 
hospital data utilizing symmetric encryption, asymmetric 
key-wrapping, hashing, and a mathematical auth code.

Algorithms used & Why:
- AES-128 CBC: For fast and secure symmetric encryption of large patient data.
- RSA (PKCS1_OAEP): To securely encrypt (wrap) the AES key for transmission.
- ElGamal (Raw Math): Implemented manually for educational purposes to create an encrypted authentication code.
- SHA-256: Hashing used to guarantee data integrity across the pipeline.

Roles:
- Sender (encrypts and signs data)
- Receiver (verifies and decrypts data)

How to run:
Run `python q2_hospital_aes_elgamal_rsa.py` and provide 
requested inputs like AES key (16 chars), primes, etc.
"""

# ============================================================
# SECTION: IMPORTS — Required modules
# ============================================================
import hashlib, os  # For hashing and OS file operations
from Crypto.Cipher import AES, PKCS1_OAEP  # For AES symmetric encryption and RSA OAEP
from Crypto.Util.Padding import pad, unpad  # For block padding in AES CBC
from Crypto.PublicKey import RSA  # For RSA key generation

# ============================================================
# SECTION: CRYPTO FUNCTIONS — Hashing
# ============================================================

# Computes the SHA-256 hash of the given data.
# Converts string to bytes if needed.
# Parameters: data (bytes or str)
# Returns: hex string of the hash
def hash_data(data):
    """Compute SHA-256 hash using hashlib."""
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()  # Compute and return hash

# ============================================================
# SECTION: MAIN EXECUTION — Pipeline flow
# ============================================================

# Main pipeline function handling encryption, transmission, and decryption
# Parameters: None
# Returns: None
def main():
    print("=== Hospital Pipeline (AES + RSA + ElGamal) ===")
    
    # Step 1: Create patient data and save to file
    patient_data = input("Enter patient data: ")  # Get raw data
    with open("patient_data.txt", "w") as f:
        f.write(patient_data)  # Save plaintext to file
    print("[+] patient_data.txt created.")
    
    # Step 2: Read back the data for processing
    with open("patient_data.txt", "r") as f:
        msg = f.read()  # Load plaintext from file
        
    # Step 3: AES Encrypt the data
    # SENDER ONLY: AES encryption is performed by the sender
    aes_key = input("Enter 16-char AES key: ")
    while len(aes_key) != 16:  # Validate AES key length
        aes_key = input("Key must be 16 chars: ")
    aes_iv = input("Enter 16-char IV: ")
    while len(aes_iv) != 16:  # Validate AES IV length
        aes_iv = input("IV must be 16 chars: ")
        
    # Initialize AES cipher in CBC mode
    cipher_aes = AES.new(aes_key.encode(), AES.MODE_CBC, aes_iv.encode())
    # Pad the message to block size and encrypt
    aes_ciphertext = cipher_aes.encrypt(pad(msg.encode(), AES.block_size))
    # Save the ciphertext to a file
    with open("encrypted_data.txt", "w") as f:
        f.write(aes_ciphertext.hex())  # Save as hex
    print("[+] encrypted_data.txt saved (hex).")
    
    # Step 4: RSA Encrypt AES Key
    # We encrypt the symmetric AES key using RSA (Key Wrapping)
    print("\nGenerating RSA keys...")
    rsa_key = RSA.generate(2048)  # Generate RSA key pair for the receiver
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())  # Init RSA cipher with public key
    enc_aes_key = cipher_rsa.encrypt(aes_key.encode())  # Encrypt AES key
    # Save encrypted AES key
    with open("encrypted_aes_key.txt", "w") as f:
        f.write(enc_aes_key.hex())  # Save as hex
    print("[+] encrypted_aes_key.txt saved (hex).")
    
    # Step 5: ElGamal Auth Code Generation (Raw Math)
    # Using raw math (pow, mod) for educational purposes
    print("\n--- ElGamal Auth Code (Raw Math) ---")
    auth_code = int(input("Enter Auth Code (integer): "))  # Get secret auth code
    p = int(input("Enter prime p: "))  # Prime modulus
    g = int(input("Enter generator g: "))  # Generator
    x = int(input("Enter private key x: "))  # Sender's private key for ElGamal
    y = pow(g, x, p)  # Compute public key y = g^x mod p
    k = int(input(f"Enter ephemeral key k (1 < k < {p-1}): "))  # Random k
    
    # Compute ciphertext components (c1, c2)
    c1 = pow(g, k, p)  # c1 = g^k mod p
    c2 = (auth_code * pow(y, k, p)) % p  # c2 = m * y^k mod p
    print("[+] Auth code encrypted via ElGamal.")
    
    # Step 6: Display Data simulating transmission
    print("\n=== TRANSMISSION DATA ===")
    print(f"Encrypted MSG (hex): {aes_ciphertext.hex()}")  # The AES ciphertext
    print(f"RSA Public Key (n, e): ({rsa_key.n}, {rsa_key.e})")  # Receiver's RSA pub key
    print(f"ElGamal Public Key (p, g, y): ({p}, {g}, {y})")  # ElGamal pub key parameters
    print(f"ElGamal Ciphertext (c1, c2): ({c1}, {c2})")  # ElGamal encrypted auth code
    
    # Step 7: Hash generation for integrity
    sender_hash = hash_data(aes_ciphertext)  # Compute hash of the ciphertext
    print(f"\nSender SHA-256 Hash: {sender_hash}")
    
    # Step 8: Receiver side - Integrity Verification
    print("\n=== RECEIVER ===")
    # INTEGRITY CHECK: Recompute SHA-256 hash of encrypted data
    # and compare with the stored hash to detect tampering
    receiver_hash = hash_data(aes_ciphertext)  # Recompute hash
    
    # SECURITY: Only decrypt if the hashes match
    if sender_hash == receiver_hash:
        print("[+] Integrity MATCH. Proceeding to decrypt.")
        
        # Step 9: Decryption Process
        # A) Decrypt AES Key using RSA private key
        dec_cipher_rsa = PKCS1_OAEP.new(rsa_key)  # Init RSA with private key
        dec_aes_key = dec_cipher_rsa.decrypt(enc_aes_key)  # Unwrap the AES key
        print(f"Decrypted AES Key: {dec_aes_key.decode()}")
        
        # B) Decrypt Message using AES key
        dec_cipher_aes = AES.new(dec_aes_key, AES.MODE_CBC, aes_iv.encode())  # Init AES
        # Decrypt and unpad
        dec_msg = unpad(dec_cipher_aes.decrypt(aes_ciphertext), AES.block_size).decode()
        print(f"Decrypted Message: {dec_msg}")
        
        # C) ElGamal decrypt (Raw Math)
        s = pow(c1, x, p)  # Compute shared secret s = c1^x mod p
        s_inv = pow(s, -1, p)  # Compute modular inverse of s
        dec_auth = (c2 * s_inv) % p  # Recover auth code m = c2 * s^-1 mod p
        print(f"Decrypted Auth Code: {dec_auth}")
        
    # Step 10: Tampering Demonstration
    print("\n=== TAMPERING DEMO ===")
    tampered_bytes = bytearray(aes_ciphertext)  # Convert to mutable bytearray
    tampered_bytes[0] ^= 0xFF  # Flip bits in the first byte to simulate tampering
    tampered_hash = hash_data(bytes(tampered_bytes))  # Hash the tampered data
    print(f"Tampered Hash: {tampered_hash}")
    
    # INTEGRITY CHECK: Verify the tampered hash against original
    if sender_hash != tampered_hash:
        print("MISMATCH! Integrity FAILED — decryption blocked.")  # Expected behavior
        
if __name__ == "__main__":
    main()
