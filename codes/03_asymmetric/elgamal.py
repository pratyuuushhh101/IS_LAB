# from secrets import randbelow
# from math import gcd


# # Parameters: a (int), p (int) -> Output: int
# def mod_inverse(a, p):
#     return pow(a, -1, p)


# # Parameters: p (int), g (int), x (int or None) -> Output: tuple[tuple[int, int, int], int]
# def keygen(p, g, x=None):
#     if x is None:
#         x = randbelow(p - 2) + 1

#     y = pow(g, x, p)
#     return (p, g, y), x


# # Parameters: m (int), public_key (tuple[int, int, int]), k (int or None) -> Output: tuple[int, int]
# def encrypt_int(m, public_key, k=None):
#     p, g, y = public_key

#     if not 0 <= m < p:
#         raise ValueError("Message integer must be smaller than p.")

#     if k is None:
#         k = randbelow(p - 2) + 1

#     c1 = pow(g, k, p)
#     s = pow(y, k, p)
#     c2 = (m * s) % p

#     return c1, c2


# # Parameters: ciphertext (tuple[int, int]), private_key (int), p (int) -> Output: int
# def decrypt_int(ciphertext, private_key, p):
#     c1, c2 = ciphertext
#     s = pow(c1, private_key, p)
#     m = (c2 * mod_inverse(s, p)) % p
#     return m


# # Parameters: text (str) -> Output: int
# def text_to_int(text):
#     return int.from_bytes(text.encode(), "big")


# # Parameters: value (int) -> Output: str
# def int_to_text(value):
#     length = max(1, (value.bit_length() + 7) // 8)
#     return value.to_bytes(length, "big").decode()


# if __name__ == "__main__":
#     p = int(input("Enter prime p: "))
#     g = int(input("Enter generator g: "))
#     x = int(input("Enter private key x: "))

#     plaintext = input("Enter short plaintext: ")
#     m = text_to_int(plaintext)

#     public, private = keygen(p, g, x)

#     try:
#         ciphertext = encrypt_int(m, public)
#         recovered = int_to_text(decrypt_int(ciphertext, private, p))

#         print("Public key:", public)
#         print("Private key:", private)
#         print("Ciphertext (c1,c2):", ciphertext)
#         print("Decrypted:", recovered)
#         print("Verification:", recovered == plaintext)
#     except ValueError as e:
#         print("Error:", e)
from secrets import randbelow
from math import gcd


# Parameters: a (int), p (int) -> Output: int
def mod_inverse(a, p):
    return pow(a, -1, p)


# Parameters: p (int), g (int), x (int or None) -> Output: tuple[tuple[int, int, int], int]
def keygen(p, g, x=None):
    if x is None:
        x = randbelow(p - 2) + 1
    
    y = pow(g, x, p)
    return (p, g, y), x


# Parameters: m (int), public_key (tuple[int, int, int]), k (int or None) -> Output: tuple[int, int]
def encrypt_int(m, public_key, k=None):
    p, g, y = public_key
    
    if not 0 <= m < p:
        raise ValueError(f"Message integer must be smaller than p. Got m={m}, p={p}")
    
    if k is None:
        k = randbelow(p - 2) + 1
    
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    
    return c1, c2


# Parameters: ciphertext (tuple[int, int]), private_key (int), p (int) -> Output: int
def decrypt_int(ciphertext, private_key, p):
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    m = (c2 * mod_inverse(s, p)) % p
    return m


# Parameters: text (str) -> Output: int
def text_to_int(text):
    return int.from_bytes(text.encode(), "big")


# Parameters: value (int) -> Output: str
def int_to_text(value):
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big").decode()


if __name__ == "__main__":
    print("="*60)
    print("ElGamal Encryption - FIXED VERSION")
    print("="*60)
    
    p = int(input("\nEnter prime p (recommended: 10007): "))
    g = int(input("Enter generator g (recommended: 5): "))
    x = int(input("Enter private key x (recommended: 3571): "))
    k_input = input("Enter k for deterministic encryption (or press Enter for random): ").strip()
    k = int(k_input) if k_input else None

    
    mode = input("\nChoose mode:\n  1. Integer input (smaller, direct control)\n  2. Text input (automatic encoding)\n  Enter choice (1 or 2): ")
    
    if mode == "1":
        # Direct integer input
        m = int(input(f"Enter plaintext as integer (must be < {p}): "))
        
    else:
        # Text input with modulo reduction
        plaintext = input("Enter plaintext (text will be encoded to integer): ")
        m_full = text_to_int(plaintext)
        m = m_full % p
        
        print(f"\n--- Text Encoding ---")
        print(f"Plaintext: '{plaintext}'")
        print(f"Encoded to integer: {m_full}")
        print(f"Reduced (mod {p}): {m}")
        print(f"Constraint check (m < p): {m} < {p}? {m < p} {'✓' if m < p else '✗'}")
    
    # Key generation
    public, private = keygen(p, g, x)
    
    try:
        # Encryption
        if k is not None:
            c1, c2 = encrypt_int(m, public, k=k)
            print(f"\n--- Encryption (with fixed k={k}) ---")
        else:
            c1, c2 = encrypt_int(m, public)
            print(f"\n--- Encryption (random k) ---")
        
        print(f"Plaintext m: {m}")
        print(f"c1 (= g^k mod p): {c1}")
        print(f"c2 (= m·y^k mod p): {c2}")
        print(f"Ciphertext: ({c1}, {c2})")
        
        # Decryption
        m_recovered = decrypt_int((c1, c2), private, p)
        
        print(f"\n--- Decryption ---")
        print(f"Recovered m: {m_recovered}")
        print(f"Verification (m == m_recovered): {m == m_recovered} {'✓' if m == m_recovered else '✗'}")
        
        # Display results
        print(f"\n--- Results ---")
        print(f"Public key (p, g, y): {public}")
        print(f"Private key (x): {private}")
        
        if mode == "2":
            try:
                plaintext_recovered = int_to_text(m_recovered)
                print(f"Recovered plaintext: '{plaintext_recovered}'")
            except:
                print(f"Could not decode back to text (m is too small)")
    
    except ValueError as e:
        print(f"\n❌ Error: {e}")
        print(f"\n💡 Fix: Use a larger p (try p=10007)")