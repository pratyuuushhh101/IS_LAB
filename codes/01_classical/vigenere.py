from alphabet import choose_alphabet


# Parameters: text (str), key (str), alphabet (str) -> Output: str
def encrypt(text, key, alphabet):
    key = "".join(ch for ch in key if ch in alphabet)
    if not key:
        raise ValueError("Key must contain characters from the alphabet.")

    n = len(alphabet)
    result = []
    key_index = 0

    for ch in text:
        if ch in alphabet:
            shift = alphabet.index(key[key_index % len(key)])
            result.append(alphabet[(alphabet.index(ch) + shift) % n])
            key_index += 1
        else:
            result.append(ch)

    return "".join(result)


# Parameters: text (str), key (str), alphabet (str) -> Output: str
def decrypt(text, key, alphabet):
    key = "".join(ch for ch in key if ch in alphabet)
    if not key:
        raise ValueError("Key must contain characters from the alphabet.")

    n = len(alphabet)
    result = []
    key_index = 0

    for ch in text:
        if ch in alphabet:
            shift = alphabet.index(key[key_index % len(key)])
            result.append(alphabet[(alphabet.index(ch) - shift) % n])
            key_index += 1
        else:
            result.append(ch)

    return "".join(result)


if __name__ == "__main__":
    alphabet = choose_alphabet()
    plaintext = input("Enter plaintext: ")
    key = input("Enter Vigenere key: ")

    ciphertext = encrypt(plaintext, key, alphabet)
    recovered = decrypt(ciphertext, key, alphabet)

    print("\nCiphertext:", ciphertext)
    print("Decrypted:", recovered)
    print("Verification:", recovered == plaintext)
