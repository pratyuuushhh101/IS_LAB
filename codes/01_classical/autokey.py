from alphabet import choose_alphabet


# Parameters: text (str), numeric_key (int), alphabet (str) -> Output: str
def encrypt(text, numeric_key, alphabet):
    n = len(alphabet)
    stream = [numeric_key]
    result = []
    plain_values = []

    for ch in text:
        if ch in alphabet:
            x = alphabet.index(ch)
            shift = stream[len(plain_values)]
            result.append(alphabet[(x + shift) % n])
            plain_values.append(x)
            stream.append(x)
        else:
            result.append(ch)

    return "".join(result)


# Parameters: text (str), numeric_key (int), alphabet (str) -> Output: str
def decrypt(text, numeric_key, alphabet):
    n = len(alphabet)
    key_stream = [numeric_key]
    result = []
    plain_values = []

    for ch in text:
        if ch in alphabet:
            c = alphabet.index(ch)
            shift = key_stream[len(plain_values)]
            p = (c - shift) % n
            result.append(alphabet[p])
            plain_values.append(p)
            key_stream.append(p)
        else:
            result.append(ch)

    return "".join(result)


if __name__ == "__main__":
    alphabet = choose_alphabet()
    plaintext = input("Enter plaintext: ")
    key = int(input("Enter numeric starting key: "))

    ciphertext = encrypt(plaintext, key, alphabet)
    recovered = decrypt(ciphertext, key, alphabet)

    print("\nCiphertext:", ciphertext)
    print("Decrypted:", recovered)
    print("Verification:", recovered == plaintext)
