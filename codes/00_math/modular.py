def gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a, b):
    if b == 0:
        return abs(a), 1 if a >= 0 else -1, 0

    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} modulo {m}.")
    return x % m


def mod_pow(base, exponent, modulus):
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")
    result = 1
    base %= modulus

    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2

    return result


if __name__ == "__main__":
    a = int(input("Enter a: "))
    m = int(input("Enter modulus m: "))

    print("gcd(a, m) =", gcd(a, m))
    print("a^5 mod m =", mod_pow(a, 5, m))

    try:
        print("modular inverse =", mod_inverse(a, m))
    except ValueError as e:
        print(e)
