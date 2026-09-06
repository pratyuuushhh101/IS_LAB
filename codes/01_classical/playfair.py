def build_matrix(keyword):
    keyword = keyword.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    sequence = []
    for ch in keyword + alphabet:
        if ch in alphabet and ch not in sequence:
            sequence.append(ch)

    return [sequence[i:i + 5] for i in range(0, 25, 5)]


def positions(matrix):
    return {
        matrix[r][c]: (r, c)
        for r in range(5)
        for c in range(5)
    }


def prepare_plaintext(text):
    text = "".join(ch for ch in text.upper() if ch.isalpha()).replace("J", "I")
    pairs = []
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 >= len(text):
            pairs.append(a + "X")
            i += 1
        elif text[i + 1] == a:
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + text[i + 1])
            i += 2

    return pairs


def transform_pair(a, b, matrix, encrypting=True):
    pos = positions(matrix)
    ra, ca = pos[a]
    rb, cb = pos[b]

    if ra == rb:
        step = 1 if encrypting else -1
        return (
            matrix[ra][(ca + step) % 5],
            matrix[rb][(cb + step) % 5],
        )

    if ca == cb:
        step = 1 if encrypting else -1
        return (
            matrix[(ra + step) % 5][ca],
            matrix[(rb + step) % 5][cb],
        )

    return matrix[ra][cb], matrix[rb][ca]


def encrypt(text, keyword):
    matrix = build_matrix(keyword)
    pairs = prepare_plaintext(text)
    return "".join(
        transform_pair(a, b, matrix, True)[0:2]
        for a, b in pairs
    ), matrix


def decrypt(text, keyword):
    matrix = build_matrix(keyword)
    text = "".join(ch for ch in text.upper() if ch.isalpha())
    if len(text) % 2:
        raise ValueError("Playfair ciphertext must have even length.")

    result = []
    for i in range(0, len(text), 2):
        a, b = transform_pair(text[i], text[i + 1], matrix, False)
        result.extend([a, b])

    return "".join(result), matrix


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    keyword = input("Enter Playfair keyword: ")

    ciphertext, matrix = encrypt(plaintext, keyword)
    recovered, _ = decrypt(ciphertext, keyword)

    print("\nPlayfair matrix:")
    for row in matrix:
        print(" ".join(row))

    print("\nPrepared plaintext:", "".join(
        prepare_plaintext(plaintext)
    ))
    print("Ciphertext:", ciphertext)
    print("Decrypted:", recovered)
