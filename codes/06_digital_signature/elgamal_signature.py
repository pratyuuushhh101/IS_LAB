"""
================================================================================
MODULE: ElGamal Digital Signature (Mathematical Implementation)
================================================================================
Purpose:
    Provides a complete, self-contained educational implementation of the ElGamal
    Digital Signature scheme based on the Discrete Logarithm Problem (DLP).

Mathematical Background:
    1. Public Parameters:
       - p: A large prime number
       - g: A generator (primitive root) modulo p
    2. Key Generation:
       - Private key: Choose random integer x such that 1 < x < p - 1
       - Public key: Compute y = g^x mod p. Public key is (p, g, y).
    3. Signature Generation:
       - Hash message m with SHA-256 to obtain integer h.
       - Choose random ephemeral key k such that 1 < k < p - 1 and gcd(k, p - 1) = 1.
       - Compute r = g^k mod p.
       - Compute modular inverse k_inv = k^(-1) mod (p - 1).
       - Compute s = (h - x * r) * k_inv mod (p - 1).
       - Signature is the pair (r, s).
    4. Signature Verification:
       - Verify bounds: 0 < r < p and 0 < s < p - 1.
       - Hash message m to obtain integer h.
       - Verify identity: g^h ≡ (y^r * r^s) (mod p).
       - Proof: (y^r * r^s) ≡ (g^(x*r) * g^(k*s)) ≡ g^(x*r + k*s)
                Since s ≡ (h - x*r) * k^(-1) (mod p-1),
                k*s ≡ h - x*r (mod p-1) => x*r + k*s ≡ h (mod p-1).
                By Fermat's Little Theorem, g^h ≡ y^r * r^s (mod p).

How to Run:
    python3 elgamal_signature.py
================================================================================
"""

import hashlib
import datetime
import random

# ==============================================================================
# SECTION: NUMBER THEORETIC HELPERS
# ==============================================================================

def gcd(a: int, b: int) -> int:
    """
    Computes the Greatest Common Divisor (GCD) using the Euclidean Algorithm.
    
    Parameters:
        a (int), b (int): Integers to find the GCD for.
        
    Returns:
        int: The greatest common divisor.
    """
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(a: int, m: int) -> int:
    """
    Computes the Modular Multiplicative Inverse of a modulo m using Extended GCD.
    Solves for x in: (a * x) % m == 1.
    
    Parameters:
        a (int): Base number.
        m (int): Modulus (must be coprime to a).
        
    Returns:
        int: The modular inverse x in range [1, m - 1].
    """
    m0 = m
    y = 0
    x = 1

    # Base case: if modulus is 1, inverse is 0
    if m == 1:
        return 0

    # Extended Euclidean algorithm loop
    while a > 1:
        q = a // m          # Quotient
        t = m
        m = a % m           # Remainder
        a = t
        t = y
        y = x - q * y       # Update y
        x = t

    # Ensure x is positive
    if x < 0:
        x = x + m0

    return x


# ==============================================================================
# SECTION: KEY GENERATION
# ==============================================================================

def generate_keys(p: int, g: int, x: int = None):
    """
    Generates an ElGamal key pair from public domain parameters p and g.
    
    Parameters:
        p (int): Prime modulus.
        g (int): Generator modulo p.
        x (int, optional): Explicit private key. If None, chosen randomly.
        
    Returns:
        tuple: (public_key, private_key) where public_key = (p, g, y) and private_key = x.
    """
    # Step 1: Select private key x in range [2, p - 2]
    if x is None:
        x = random.randint(2, p - 2)
        
    # Step 2: Compute public key component y = g^x mod p
    y = pow(g, x, p)
    
    public_key = (p, g, y)
    private_key = x
    return public_key, private_key


# ==============================================================================
# SECTION: SIGNATURE GENERATION
# ==============================================================================

def sign(message_str: str, p: int, g: int, x: int, k: int = None):
    """
    Signs a message string using the ElGamal Digital Signature algorithm.
    
    Parameters:
        message_str (str): Plaintext message to be signed.
        p (int): Prime modulus.
        g (int): Generator.
        x (int): Signer's private key.
        k (int, optional): Ephemeral secret. If None, chosen randomly.
        
    Returns:
        tuple: Signature pair (r, s).
    """
    # Step 1: Hash the message using SHA-256 and convert hex digest to integer
    hash_hex = hashlib.sha256(message_str.encode('utf-8')).hexdigest()
    h = int(hash_hex, 16)
    
    # Step 2: Choose a random ephemeral integer k coprime to (p - 1)
    if k is None:
        while True:
            k = random.randint(2, p - 2)
            if gcd(k, p - 1) == 1:
                break
    else:
        if gcd(k, p - 1) != 1:
            raise ValueError("Ephemeral key k and (p - 1) must be coprime!")
            
    # Step 3: Compute signature component r = g^k mod p
    r = pow(g, k, p)
    
    # Step 4: Compute modular inverse of k modulo (p - 1)
    k_inv = mod_inverse(k, p - 1)
    
    # Step 5: Compute signature component s = ((h - x * r) * k_inv) mod (p - 1)
    # Note: Python's modulo correctly handles negative values for (h - x * r)
    s = ((h - x * r) * k_inv) % (p - 1)
    
    # Rare boundary check: if s == 0, a new random k must be chosen
    if s == 0 and k is None:
        return sign(message_str, p, g, x)
        
    return r, s


# ==============================================================================
# SECTION: SIGNATURE VERIFICATION
# ==============================================================================

def verify(message_str: str, r: int, s: int, p: int, g: int, y: int) -> bool:
    """
    Verifies an ElGamal Digital Signature (r, s) against a message and public key.
    
    Parameters:
        message_str (str): Original message.
        r (int), s (int): Digital signature components.
        p (int), g (int), y (int): Public key parameters.
        
    Returns:
        bool: True if signature is valid, False otherwise.
    """
    # Step 1: Verify boundary constraints on r and s
    if not (0 < r < p) or not (0 < s < p - 1):
        return False
        
    # Step 2: Recompute message hash h = SHA-256(m) as an integer
    hash_hex = hashlib.sha256(message_str.encode('utf-8')).hexdigest()
    h = int(hash_hex, 16)
    
    # Step 3: Compute verification sides modulo p:
    # Left side:  v1 = g^h mod p
    # Right side: v2 = (y^r * r^s) mod p
    left_side = pow(g, h, p)
    right_side = (pow(y, r, p) * pow(r, s, p)) % p
    
    # Step 4: If left_side == right_side, the signature is authentic and valid
    return left_side == right_side


# ==============================================================================
# SECTION: MAIN DEMONSTRATION
# ==============================================================================

if __name__ == '__main__':
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] --- ElGamal Digital Signature Demo ---")
    try:
        # User input for parameters (suggesting safe toy/educational numbers)
        print("\nTip: You can use educational parameters such as p=7919, g=2")
        p = int(input("Enter large prime p: "))
        g = int(input("Enter generator g: "))
        x_in = input("Enter private key x (or press enter for random): ")
        x = int(x_in) if x_in.strip() else None
        
        # Message input
        msg = input("\nEnter message to sign: ")
        
        # Key generation
        pub, priv = generate_keys(p, g, x)
        print(f"\n[+] Generated Public Key (p, g, y): {pub}")
        print(f"[+] Private Key x: {priv}")
        
        # Signing
        r, s = sign(msg, pub[0], pub[1], priv)
        print(f"\n[+] Generated Signature (r, s):\n    r = {r}\n    s = {s}")
        
        # Verification
        is_valid = verify(msg, r, s, pub[0], pub[1], pub[2])
        print(f"\n[+] Verification Check Result: {'VALID (Authentic)' if is_valid else 'INVALID'}")
        
        # Tampering demonstration
        tampered_msg = msg + "!"
        is_tampered_valid = verify(tampered_msg, r, s, pub[0], pub[1], pub[2])
        print(f"[+] Tampered Message Check Result: {'VALID' if is_tampered_valid else 'INVALID (Tampering detected!)'}")
        
    except Exception as e:
        print(f"\n[-] Error: {e}")
