from math import gcd
from alphabet import choose_alphabet


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
        raise ValueError("Multiplicative key has no inverse.")
    return x % m


# Parameters: text (str), a (int), b (int), alphabet (str) -> Output: str
def encrypt(text, a, b, alphabet):
    n = len(alphabet)

    if gcd(a, n) != 1:
        raise ValueError(f"a={a} is invalid because gcd(a,{n}) != 1.")

    return "".join(
        alphabet[(a * alphabet.index(ch) + b) % n]
        if ch in alphabet else ch
        for ch in text
    )


# Parameters: text (str), a (int), b (int), alphabet (str) -> Output: str
def decrypt(text, a, b, alphabet):
    n = len(alphabet)
    a_inv = mod_inverse(a, n)

    return "".join(
        alphabet[(a_inv * (alphabet.index(ch) - b)) % n]
        if ch in alphabet else ch
        for ch in text
    )


if __name__ == "__main__":
    alphabet = choose_alphabet()
    plaintext = input("Enter plaintext: ")
    a = int(input("Enter multiplicative key a: "))
    b = int(input("Enter additive key b: "))

    try:
        ciphertext = encrypt(plaintext, a, b, alphabet)
        recovered = decrypt(ciphertext, a, b, alphabet)

        print("\nCiphertext:", ciphertext)
        print("Decrypted:", recovered)
        print("Verification:", recovered == plaintext)
    except ValueError as e:
        print("Error:", e)
