from alphabet import choose_alphabet


def encrypt(text, key, alphabet):
    n = len(alphabet)
    result = ""

    for ch in text:
        if ch in alphabet:
            result += alphabet[(alphabet.index(ch) + key) % n]
        else:
            result += ch

    return result


def decrypt(text, key, alphabet):
    return encrypt(text, -key, alphabet)


if __name__ == "__main__":
    alphabet = choose_alphabet()
    plaintext = input("Enter plaintext: ")
    key = int(input("Enter additive key: "))

    ciphertext = encrypt(plaintext, key, alphabet)
    recovered = decrypt(ciphertext, key, alphabet)

    print("\nCiphertext:", ciphertext)
    print("Decrypted:", recovered)
    print("Verification:", recovered == plaintext)
