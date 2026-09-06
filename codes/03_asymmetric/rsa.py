from math import gcd
from secrets import randbelow
from sympy import nextprime


# Parameters: a (int), m (int) -> Output: int
def mod_inverse(a, m):
    # Parameters: x (int), y (int) -> Output: tuple[int, int, int]
    def egcd(x, y):
        if y == 0:
            return x, 1, 0
        g, p, q = egcd(y, x % y)
        return g, q, p - (x // y) * q

    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse.")
    return x % m


# Parameters: p (int), q (int), e (int) -> Output: tuple[tuple[int, int], tuple[int, int]]
def generate_keypair(p, q, e=65537):
    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)
    return (n, e), (n, d)


# Parameters: m (int), public_key (tuple[int, int]) -> Output: int
def encrypt_int(m, public_key):
    n, e = public_key
    if not 0 <= m < n:
        raise ValueError("Message integer must satisfy 0 <= m < n.")
    return pow(m, e, n)


# Parameters: c (int), private_key (tuple[int, int]) -> Output: int
def decrypt_int(c, private_key):
    n, d = private_key
    return pow(c, d, n)


# Parameters: text (str) -> Output: int
def text_to_int(text):
    return int.from_bytes(text.encode(), "big")


# Parameters: value (int) -> Output: str
def int_to_text(value):
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big").decode()


if __name__ == "__main__":
    print("Educational RSA demonstration")
    p = int(input("Enter prime p: "))
    q = int(input("Enter prime q: "))
    plaintext = input("Enter short plaintext: ")

    public, private = generate_keypair(p, q)
    m = text_to_int(plaintext)

    print("Public key:", public)
    print("Private key:", private)

    if m >= public[0]:
        print("Message is too large for this toy RSA modulus.")
    else:
        c = encrypt_int(m, public)
        recovered = int_to_text(decrypt_int(c, private))

        print("Plaintext integer:", m)
        print("Ciphertext:", c)
        print("Recovered plaintext:", recovered)
        print("Verification:", recovered == plaintext)
