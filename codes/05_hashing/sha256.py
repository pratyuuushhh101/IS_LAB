"""
================================================================================
MODULE: SHA-256 Hashing Utilities
================================================================================
Purpose:
    Provides standalone utility functions for computing SHA-256 digests of strings,
    raw bytes, and entire disk files, along with data integrity verification.

Cryptographic Concept:
    SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that
    takes an arbitrary block of data and returns a fixed-size 256-bit (32-byte / 
    64-character hexadecimal) digest.
    Key properties:
    1. Deterministic: Same input always produces the exact same hash.
    2. Quick computation: Fast to calculate for any given data.
    3. Pre-image resistance: Infeasible to regenerate the original message from its hash.
    4. Avalanche effect: A tiny change in input drastically changes the resulting hash.
    5. Collision resistance: Infeasible to find two different inputs with the same hash.

How to Run:
    python3 sha256.py
================================================================================
"""

import hashlib
import datetime
import os

# ==============================================================================
# HASHING FUNCTIONS
# ==============================================================================

def hash_text(text: str) -> str:
    """
    Computes the SHA-256 hexadecimal digest of an input string.

    Parameters:
        text (str): The plain text string to hash.

    Returns:
        str: 64-character hexadecimal representation of the 256-bit hash.
    """
    # Step 1: Encode the string to UTF-8 bytes (hashlib operates on byte sequences)
    data_bytes = text.encode('utf-8')
    
    # Step 2: Pass bytes into sha256 and generate the hexadecimal string
    return hashlib.sha256(data_bytes).hexdigest()


def hash_bytes(data: bytes) -> str:
    """
    Computes the SHA-256 hexadecimal digest of raw bytes.

    Parameters:
        data (bytes): Byte array or byte string to hash.

    Returns:
        str: 64-character hexadecimal representation of the hash.
    """
    # Direct hash computation on raw byte sequence
    return hashlib.sha256(data).hexdigest()


def hash_file(filepath: str) -> str:
    """
    Computes the SHA-256 hexadecimal digest of a file on disk.
    Reads the file in 4KB chunks to efficiently handle large files without
    loading the entire file into memory.

    Parameters:
        filepath (str): Path to the target file.

    Returns:
        str: 64-character hexadecimal digest of the file contents.
    """
    # Initialize the SHA-256 hash accumulator object
    hasher = hashlib.sha256()
    
    # Open file in binary read mode ('rb')
    with open(filepath, 'rb') as f:
        # Read file sequentially in 4096-byte (4KB) chunks until EOF (b'')
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)  # Feed chunk into hash accumulator
            
    # Return the final hexadecimal digest
    return hasher.hexdigest()


# ==============================================================================
# INTEGRITY VERIFICATION
# ==============================================================================

def verify_integrity(data, expected_hash: str) -> bool:
    """
    Verifies the integrity of data by recomputing its SHA-256 hash and 
    comparing it against an expected hash value.

    Parameters:
        data (str or bytes): The data to verify.
        expected_hash (str): The reference/original hash value to match.

    Returns:
        bool: True if computed hash matches expected_hash (data untampered),
              False otherwise.
    """
    # Check type of data and calculate current hash accordingly
    if isinstance(data, str):
        actual_hash = hash_text(data)
    elif isinstance(data, bytes):
        actual_hash = hash_bytes(data)
    else:
        raise ValueError('Data must be either str or bytes')
    
    # Constant-time comparison or direct equality check
    return actual_hash.lower() == expected_hash.lower()


# ==============================================================================
# MAIN DEMONSTRATION
# ==============================================================================

if __name__ == '__main__':
    # Print header with timestamp
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] --- SHA-256 Hashing Demo ---")
    
    # Prompt user for sample text
    text = input("Enter text to hash: ")
    h = hash_text(text)
    print(f"\n[+] Computed SHA-256 Hash:\n    {h}")
    
    # Test integrity verification
    print("\n--- Testing Integrity Verification ---")
    verify = input("Enter text to verify integrity against the above hash: ")
    if verify_integrity(verify, h):
        print("\n[SUCCESS] Integrity Verified! Data has NOT been altered.")
    else:
        print("\n[FAILED] Integrity Check FAILED! Data has been modified or mismatched.")
