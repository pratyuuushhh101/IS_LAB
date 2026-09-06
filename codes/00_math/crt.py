from modular import mod_inverse


def crt(remainders, moduli):
    if len(remainders) != len(moduli):
        raise ValueError("Remainders and moduli must have the same length.")

    N = 1
    for m in moduli:
        N *= m

    result = 0
    for a, m in zip(remainders, moduli):
        Ni = N // m
        inv = mod_inverse(Ni, m)
        result += a * Ni * inv

    return result % N


if __name__ == "__main__":
    k = int(input("How many congruences? "))
    remainders = []
    moduli = []

    for i in range(k):
        remainders.append(int(input(f"Remainder {i + 1}: ")))
        moduli.append(int(input(f"Modulus {i + 1}: ")))

    try:
        print("CRT solution =", crt(remainders, moduli))
    except ValueError as e:
        print("Error:", e)
