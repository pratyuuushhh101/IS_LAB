import numpy as np
from math import gcd
from alphabet import choose_alphabet


def matrix_inverse_mod(matrix, modulus):
    matrix = np.array(matrix, dtype=int)
    n = matrix.shape[0]

    # Cofactor/adjugate method for small exam matrices.
    if n == 2:
        a, b = matrix[0]
        c, d = matrix[1]
        det = (a * d - b * c) % modulus

        if gcd(int(det), modulus) != 1:
            raise ValueError("Key matrix is not invertible modulo alphabet size.")

        det_inv = pow(int(det), -1, modulus)
        return (det_inv * np.array([[d, -b], [-c, a]])) % modulus

    # Generic Gauss-Jordan fallback.
    aug = np.concatenate(
        [matrix % modulus, np.eye(n, dtype=int)],
        axis=1
    )

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if gcd(int(aug[row, col]), modulus) == 1:
                pivot = row
                break

        if pivot is None:
            raise ValueError("Key matrix is not invertible.")

        aug[[col, pivot]] = aug[[pivot, col]]
        inv = pow(int(aug[col, col]), -1, modulus)
        aug[col] = (aug[col] * inv) % modulus

        for row in range(n):
            if row != col:
                factor = int(aug[row, col])
                aug[row] = (aug[row] - factor * aug[col]) % modulus

    return aug[:, n:]


def process(text, key_matrix, alphabet, encrypting=True):
    n = len(alphabet)
    K = np.array(key_matrix, dtype=int) % n
    size = K.shape[0]

    text = "".join(ch for ch in text if ch in alphabet)
    while len(text) % size:
        text += alphabet[0]

    values = [alphabet.index(ch) for ch in text]
    output = []

    if encrypting:
        M = K
    else:
        M = matrix_inverse_mod(K, n)

    for i in range(0, len(values), size):
        block = np.array(values[i:i + size])
        result = M.dot(block) % n
        output.extend(alphabet[int(x)] for x in result)

    return "".join(output)


if __name__ == "__main__":
    alphabet = choose_alphabet()
    size = int(input("Enter Hill matrix size: "))

    key = []
    print(f"Enter {size} rows, each containing {size} integers.")
    for i in range(size):
        key.append([int(x) for x in input(f"Row {i + 1}: ").split()])

    plaintext = input("Enter plaintext: ")

    try:
        ciphertext = process(plaintext, key, alphabet, True)
        recovered = process(ciphertext, key, alphabet, False)

        print("\nCiphertext:", ciphertext)
        print("Decrypted:", recovered)
        print("Verification:", recovered.rstrip(alphabet[0]) == "".join(
            ch for ch in plaintext if ch in alphabet
        ))
    except ValueError as e:
        print("Error:", e)
