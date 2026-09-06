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
        raise ValueError("Message integer must be smaller than p.")

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
    p = int(input("Enter prime p: "))
    g = int(input("Enter generator g: "))
    x = int(input("Enter private key x: "))

    plaintext = input("Enter short plaintext: ")
    m = text_to_int(plaintext)

    public, private = keygen(p, g, x)

    try:
        ciphertext = encrypt_int(m, public)
        recovered = int_to_text(decrypt_int(ciphertext, private, p))

        print("Public key:", public)
        print("Private key:", private)
        print("Ciphertext (c1,c2):", ciphertext)
        print("Decrypted:", recovered)
        print("Verification:", recovered == plaintext)
    except ValueError as e:
        print("Error:", e)
