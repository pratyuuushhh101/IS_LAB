import numpy as np
from modular import mod_inverse


def matrix_mod_inverse(matrix, modulus):
    matrix = np.array(matrix, dtype=int)
    n = matrix.shape[0]

    if matrix.shape[0] != matrix.shape[1]:
        raise ValueError("Matrix must be square.")

    # Gauss-Jordan elimination over Z_mod.
    aug = np.concatenate(
        [matrix % modulus, np.eye(n, dtype=int)],
        axis=1
    )

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if np.gcd(int(aug[row, col]), modulus) == 1:
                pivot = row
                break

        if pivot is None:
            raise ValueError("Matrix is not invertible modulo the given modulus.")

        if pivot != col:
            aug[[col, pivot]] = aug[[pivot, col]]

        inv = mod_inverse(int(aug[col, col]), modulus)
        aug[col] = (aug[col] * inv) % modulus

        for row in range(n):
            if row != col:
                factor = int(aug[row, col])
                aug[row] = (aug[row] - factor * aug[col]) % modulus

    return aug[:, n:]


if __name__ == "__main__":
    n = int(input("Matrix size n: "))
    modulus = int(input("Modulus: "))

    values = []
    for i in range(n):
        values.append([
            int(x) for x in input(f"Row {i + 1}: ").split()
        ])

    try:
        inv = matrix_mod_inverse(values, modulus)
        print("Inverse matrix:")
        print(inv)
    except ValueError as e:
        print("Error:", e)
