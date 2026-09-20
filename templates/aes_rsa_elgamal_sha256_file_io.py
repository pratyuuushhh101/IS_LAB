"""
=============================================================================
Template: AES Encryption, RSA Key Wrapping, ElGamal Enc, SHA-256 (File IO)
=============================================================================
PURPOSE:
This program demonstrates a sequential cryptographic pipeline involving
file I/O, encryption, digital envelopes (key wrapping), and integrity checking.

ALGORITHMS & WHY:
- AES-128 CBC: Fast symmetric encryption for the main file data.
- RSA PKCS1_OAEP: Asymmetric encryption used to wrap (encrypt) the AES key.
- ElGamal Encryption: Raw math educational implementation to encrypt an auth code.
- SHA-256: Hashing used to verify the integrity of the ciphertext.

PIPELINE STEPS:
1. Create file -> 2. Read file -> 3. AES Encrypt -> 4. RSA Wrap Key ->
5. ElGamal Encrypt Auth -> 6. Display -> 7. Hash Ciphertext -> 
8. Verify Hash -> 9. Decrypt (if match) -> 10. Tampering Demo

HOW TO RUN:
Simply run the script. It executes sequentially with no user interaction.

# CUSTOMIZE: Change file names, AES parameters, and ElGamal parameters below.
=============================================================================
"""

import hashlib
import datetime
import random
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================

# CUSTOMIZE: File names
PLAINTEXT_FILE = "plain.txt"     # Input data file
CIPHERTEXT_FILE = "cipher.enc"   # Encrypted data output
WRAPPED_KEY_FILE = "wrapped_key.enc" # Encrypted AES key output

# CUSTOMIZE: AES Parameters
AES_KEY = os.urandom(16) # 128-bit key for AES
AES_IV = os.urandom(16)  # 16-byte Initialization Vector

# ==========================================
# CRYPTOGRAPHIC FUNCTIONS
# ==========================================

def compute_hash(data: bytes) -> str:
    """
    Computes the SHA-256 hash of the given bytes.
    Parameters:
      data: The input bytes.
    Returns:
      A hex string representation of the hash.
    """
    # Compute SHA-256 digest
    return hashlib.sha256(data).hexdigest()

def elgamal_encrypt(m: int, p: int, g: int, y: int, k: int):
    """
    Encrypts an integer message using ElGamal.
    Parameters:
      m: The plaintext message (integer).
      p: Prime modulus.
      g: Primitive root.
      y: Recipient's public key.
      k: Random ephemeral key.
    Returns:
      A tuple (c1, c2) representing the ciphertext.
    """
    # ElGamal Encryption:
    # c1 = g^k mod p (ephemeral key)
    c1 = pow(g, k, p)
    # s = y^k mod p (shared secret using recipient's public key)
    s = pow(y, k, p)
    # c2 = (m * s) mod p (message masked with shared secret)
    c2 = (m * s) % p
    return c1, c2

def elgamal_decrypt(c1: int, c2: int, p: int, x: int):
    """
    Decrypts ElGamal ciphertext back to an integer.
    Parameters:
      c1, c2: The ciphertext components.
      p: Prime modulus.
      x: Recipient's private key.
    Returns:
      The original integer message.
    """
    # ElGamal Decryption:
    # s = c1^x mod p (recover shared secret using private key)
    s = pow(c1, x, p)
    # s_inv = s^-1 mod p (modular inverse of the shared secret)
    s_inv = pow(s, -1, p)
    # m = (c2 * s_inv) mod p (unmask message)
    m = (c2 * s_inv) % p
    return m

# ==========================================
# MAIN PIPELINE
# ==========================================

def main():
    """
    Main function executing the step-by-step cryptographic pipeline.
    Parameters:
      None
    Returns:
      None
    """
    # Step 1: Create a file with plaintext data
    print(f"[{datetime.datetime.now()}] Step 1: Create file with user content")
    with open(PLAINTEXT_FILE, "w") as f:
        # Write dummy confidential data
        f.write("Highly confidential data for file I/O template.")
    print("Content saved to", PLAINTEXT_FILE)
    
    # Step 2: Read the file back into memory
    print(f"[{datetime.datetime.now()}] Step 2: Read file")
    with open(PLAINTEXT_FILE, "r") as f:
        content = f.read()
    print("Read content:", content)
    
    # Step 3: Encrypt the content using AES-128 CBC and save it
    print(f"[{datetime.datetime.now()}] Step 3: AES-128 CBC encrypt and save")
    # Initialize AES cipher
    cipher_aes = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    # Pad and encrypt the content
    ciphertext = cipher_aes.encrypt(pad(content.encode(), AES.block_size))
    with open(CIPHERTEXT_FILE, "wb") as f:
        f.write(ciphertext)
    print("Ciphertext saved to", CIPHERTEXT_FILE)
    
    # Step 4: Wrap (encrypt) the AES key using RSA and save it (Digital Envelope)
    print(f"[{datetime.datetime.now()}] Step 4: RSA PKCS1_OAEP encrypt AES key and save")
    # Generate an RSA key pair
    rsa_key = RSA.generate(2048)
    # Initialize RSA cipher with the public key
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    # Encrypt the symmetric AES key
    wrapped_aes_key = cipher_rsa.encrypt(AES_KEY)
    with open(WRAPPED_KEY_FILE, "wb") as f:
        f.write(wrapped_aes_key)
    print("Wrapped AES key saved to", WRAPPED_KEY_FILE)
    
    # Step 5: Encrypt an authorization code using ElGamal
    print(f"[{datetime.datetime.now()}] Step 5: ElGamal encrypt auth code")
    # CUSTOMIZE: ElGamal parameters
    p = 7919
    g = 2
    x = 3456
    y = pow(g, x, p)
    k = random.randint(2, p-2)
    auth_code = 1234
    
    # Call ElGamal encryption
    c1, c2 = elgamal_encrypt(auth_code, p, g, y, k)
    print(f"Auth code {auth_code} ElGamal encrypted to c1={c1}, c2={c2}")
    
    # Step 6: Display the encrypted artifacts
    print(f"[{datetime.datetime.now()}] Step 6: Display all encrypted values")
    print(f"AES Ciphertext (hex): {ciphertext.hex()[:32]}...")
    print(f"Wrapped AES Key (hex): {wrapped_aes_key.hex()[:32]}...")
    print(f"ElGamal Ciphertext: c1={c1}, c2={c2}")
    
    # Step 7: Compute hash of the AES ciphertext (simulating sender side)
    print(f"[{datetime.datetime.now()}] Step 7: SHA-256 hash of AES ciphertext (sender)")
    sender_hash = compute_hash(ciphertext)
    print("Sender hash:", sender_hash)
    
    # Step 8: Recompute hash (simulating receiver side) and compare for integrity
    print(f"[{datetime.datetime.now()}] Step 8: Recompute hash (receiver) and compare")
    with open(CIPHERTEXT_FILE, "rb") as f:
        loaded_ciphertext = f.read()
    receiver_hash = compute_hash(loaded_ciphertext)
    print("Receiver hash:", receiver_hash)
    
    # Verification Flow: Check integrity before proceeding
    print(f"Integrity check: {'PASS' if sender_hash == receiver_hash else 'FAIL'}")
    
    # Step 9: Decrypt the data only if the integrity check passed
    print(f"[{datetime.datetime.now()}] Step 9: Decryption if match")
    if sender_hash == receiver_hash:
        # Unwrap the AES key using the RSA private key
        cipher_rsa_dec = PKCS1_OAEP.new(rsa_key)
        decrypted_aes_key = cipher_rsa_dec.decrypt(wrapped_aes_key)
        
        # Decrypt the AES ciphertext using the unwrapped key
        cipher_aes_dec = AES.new(decrypted_aes_key, AES.MODE_CBC, AES_IV)
        decrypted_plaintext = unpad(cipher_aes_dec.decrypt(loaded_ciphertext), AES.block_size).decode()
        
        # Decrypt the ElGamal ciphertext
        decrypted_auth = elgamal_decrypt(c1, c2, p, x)
        
        print("Decrypted Content:", decrypted_plaintext)
        print("Decrypted Auth Code:", decrypted_auth)
        
    # Step 10: Demonstrate what happens when ciphertext is tampered with
    print(f"[{datetime.datetime.now()}] Step 10: TAMPERING DEMO")
    # Copy the ciphertext and flip one byte
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF # Flip a byte
    
    # Recompute the hash to show it no longer matches
    tampered_hash = compute_hash(tampered_ciphertext)
    print("Original Hash:", sender_hash)
    print("Tampered Hash:", tampered_hash)
    print("Integrity FAILED")

# Ensure the script runs when executed directly
if __name__ == "__main__":
    main()
