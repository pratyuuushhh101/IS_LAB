from alphabet import ALPHABET_26


# Parameters: ciphertext (str) -> Output: None
def additive_bruteforce(ciphertext):
    print("Additive cipher brute force:")
    for key in range(len(ALPHABET_26)):
        plaintext = "".join(
            ALPHABET_26[
                (ALPHABET_26.index(ch) - key) % 26
            ] if ch in ALPHABET_26 else ch
            for ch in ciphertext.lower()
        )
        print(f"key={key:2}: {plaintext}")


# Parameters: cipher_pair (str), plain_pair (str) -> Output: Generator[tuple[int, int]]
def affine_from_known_pair(cipher_pair, plain_pair):
    # Given plaintext "ab" -> ciphertext "GL", solve:
    # c = a*x + b mod 26.
    p1, p2 = [ALPHABET_26.index(x) for x in plain_pair.lower()]
    c1, c2 = [ALPHABET_26.index(x) for x in cipher_pair.lower()]

    for a in range(26):
        if __import__("math").gcd(a, 26) != 1:
            continue

        b = (c1 - a * p1) % 26
        if (a * p2 + b) % 26 == c2:
            yield a, b


if __name__ == "__main__":
    ciphertext = input("Enter ciphertext for additive brute force: ")
    additive_bruteforce(ciphertext)

    print("\nAffine candidates for plaintext 'ab' -> ciphertext 'GL':")
    print(list(affine_from_known_pair("GL", "ab")))
