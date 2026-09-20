"""
============================================================
RSA Digital Signature Utility
============================================================
Purpose:
This program demonstrates how digital signatures work using RSA 
and SHA-256 to ensure data integrity and authenticity.

Algorithms used & Why:
- RSA (PKCS1_v1_5): Used for generating the digital signature because it's the standard for RSA signatures, providing authenticity.
- SHA-256: Used for hashing the message before signing because signing a short fixed-length hash is much more efficient and secure than signing the whole message.

Roles/Users:
- No explicit roles in this basic script, but demonstrates a sender (signing) and receiver (verifying).

How to run:
Simply run `python rsa_signature.py` and follow the prompts.
"""

# ============================================================
# SECTION: IMPORTS — Required modules for cryptography and hashing
# ============================================================
import hashlib  # Standard library hashing (though Crypto.Hash is used below)
from Crypto.PublicKey import RSA  # For generating RSA key pairs
from Crypto.Signature import pkcs1_15  # For creating and verifying PKCS#1 v1.5 signatures
from Crypto.Hash import SHA256  # For computing the SHA-256 hash of the data

# ============================================================
# SECTION: CRYPTOGRAPHY FUNCTIONS — Key generation, signing, verifying
# ============================================================

# Generates a 2048-bit RSA key pair.
# This key size provides a good balance between security and performance.
# Parameters: None
# Returns: tuple containing (public_key object, private_key object)
def generate_keys():
    """Generates a 2048-bit RSA key pair."""
    key = RSA.generate(2048)  # Generate a new RSA key object of 2048 bits
    return key.publickey(), key  # Return the public key and the full key (which contains the private key)

# Signs data using the sender's RSA private key and PKCS1_v1_5 standard.
# The data is first hashed, then the hash is signed.
# Parameters: data (str or bytes) to sign, private_key (RSA key object)
# Returns: signature (bytes)
def sign(data, private_key):
    """Signs data using RSA private key and PKCS1_v1_5."""
    # Step 1: Convert string data to bytes if necessary
    if isinstance(data, str):
        data = data.encode()  # Encode string to bytes
    # Step 2: Compute the SHA-256 hash of the data
    hash_obj = SHA256.new(data)  # Create a new SHA-256 hash object
    # Step 3: Sign the hash using the private key
    signature = pkcs1_15.new(private_key).sign(hash_obj)  # Generate the digital signature
    return signature  # Return the binary signature

# Verifies an RSA signature using the sender's public key and PKCS1_v1_5 standard.
# It re-hashes the data and compares it against the decrypted signature.
# Parameters: data (str or bytes), signature (bytes), public_key (RSA key object)
# Returns: bool (True if valid, False otherwise)
def verify(data, signature, public_key):
    """Verifies RSA signature using public key and PKCS1_v1_5."""
    # Step 1: Convert string data to bytes if necessary
    if isinstance(data, str):
        data = data.encode()  # Encode string to bytes
    # Step 2: Recompute the SHA-256 hash of the received data
    hash_obj = SHA256.new(data)  # Create a new SHA-256 hash object
    try:
        # Step 3: Verify the signature against the computed hash using the public key
        pkcs1_15.new(public_key).verify(hash_obj, signature)  # Will raise exception if invalid
        return True  # Verification successful
    except (ValueError, TypeError):
        # Verification failed (ValueError for wrong signature, TypeError for wrong inputs)
        return False  # Verification failed

# ============================================================
# SECTION: MAIN EXECUTION — Interactive demonstration of signatures
# ============================================================
if __name__ == "__main__":
    print("=== RSA Digital Signature Utility ===")
    
    # 1. Menu option / User Input: Get the message to be signed
    message = input("Enter message to sign: ")
    
    # 2. Key Generation phase
    print("\nGenerating RSA keys...")
    pub_key, priv_key = generate_keys()  # Call the key generation function
    print("Keys generated successfully.")
    
    # 3. Signing phase
    print("\nSigning message...")
    # SENDER ONLY CAN SIGN: Only the sender has the private key to create a valid signature.
    signature = sign(message, priv_key)  # Create the digital signature
    print(f"Signature (hex): {signature.hex()}")  # Print the signature in a readable hex format
    
    # 4. Verification phase
    print("\nVerifying signature...")
    # ANYONE CAN VERIFY: The public key is used, meaning anyone can verify the sender's signature.
    is_valid = verify(message, signature, pub_key)  # Verify the signature
    
    # INTEGRITY AND AUTHENTICITY CHECK: Ensure data wasn't changed and came from the sender
    if is_valid:
        print("Signature is VALID. Integrity and authenticity confirmed.")  # Success message
    else:
        print("Signature is INVALID.")  # Failure message
        
    # 5. Tampering Demonstration phase
    print("\nDemonstrating tampering...")
    tampered_message = message + " tampered"  # Alter the original message
    
    # INTEGRITY CHECK FAIL: The hash of this tampered message will not match the signed hash
    is_valid = verify(tampered_message, signature, pub_key)  # Attempt to verify the tampered message
    
    # SECURITY: The verification must fail if the data was modified
    if is_valid:
        print("Tampered signature is VALID (Error!).")  # This should not happen
    else:
        print("Tampered signature is INVALID (Expected behavior).")  # Correct behavior
