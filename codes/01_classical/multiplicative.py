from alphabet import choose_alphabet
from math import gcd


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
        raise ValueError("Key has no modular inverse for this alphabet size.")
    return x % m


# Parameters: text (str), key (int), alphabet (str) -> Output: str
def encrypt(text, key, alphabet):
    n = len(alphabet)

    if gcd(key, n) != 1:
        raise ValueError(
            f"Key {key} is not valid. gcd({key}, {n}) must be 1."
        )

    return "".join(
        alphabet[(alphabet.index(ch) * key) % n] if ch in alphabet else ch
        for ch in text
    )


# Parameters: text (str), key (int), alphabet (str) -> Output: str
def decrypt(text, key, alphabet):
    inverse = mod_inverse(key, len(alphabet))
    return "".join(
        alphabet[(alphabet.index(ch) * inverse) % len(alphabet)]
        if ch in alphabet else ch
        for ch in text
    )


if __name__ == "__main__":
    alphabet = choose_alphabet()
    plaintext = input("Enter plaintext: ")
    key = int(input("Enter multiplicative key: "))

    try:
        ciphertext = encrypt(plaintext, key, alphabet)
        recovered = decrypt(ciphertext, key, alphabet)

        print("\nCiphertext:", ciphertext)
        print("Decrypted:", recovered)
        print("Verification:", recovered == plaintext)
    except ValueError as e:
        print("Error:", e)
