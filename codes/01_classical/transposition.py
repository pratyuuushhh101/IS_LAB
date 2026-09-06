def columnar_encrypt(text, key):
    text = "".join(text.split())
    key = key.upper()

    order = sorted(range(len(key)), key=lambda i: (key[i], i))
    columns = [""] * len(key)

    for i, ch in enumerate(text):
        columns[i % len(key)] += ch

    return "".join(columns[i] for i in order)


def columnar_decrypt(ciphertext, key):
    key = key.upper()
    n = len(key)
    length = len(ciphertext)
    rows = (length + n - 1) // n

    full_columns = length % n
    if full_columns == 0:
        full_columns = n

    order = sorted(range(n), key=lambda i: (key[i], i))
    columns = [""] * n

    index = 0
    for rank, col in enumerate(order):
        size = rows if col < full_columns else rows - 1
        columns[col] = ciphertext[index:index + size]
        index += size

    result = []
    for r in range(rows):
        for c in range(n):
            if r < len(columns[c]):
                result.append(columns[c][r])

    return "".join(result)


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    key = input("Enter columnar transposition keyword: ")

    ciphertext = columnar_encrypt(plaintext, key)
    recovered = columnar_decrypt(ciphertext, key)

    print("\nCiphertext:", ciphertext)
    print("Decrypted:", recovered)
    print("Verification:", recovered == "".join(plaintext.split()))
