from math import gcd


# Parameters: a1 (int), m1 (int), a2 (int), m2 (int) -> Output: int
def crt_pair(a1, m1, a2, m2):
    inv = pow(m1, -1, m2)
    return (a1 + m1 * ((a2 - a1) * inv % m2)) % (m1 * m2)


# Parameters: m (int), n (int) -> Output: int
def encrypt(m, n):
    return (m * m) % n


# Parameters: ciphertext (int), p (int), q (int) -> Output: list[int]
def decrypt(ciphertext, p, q):
    if p % 4 != 3 or q % 4 != 3:
        raise ValueError("Rabin requires p and q congruent to 3 modulo 4.")

    n = p * q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    r1 = crt_pair(mp, p, mq, q)
    r2 = n - r1
    r3 = crt_pair(mp, p, (-mq) % q, q)
    r4 = n - r3

    return [r1, r2, r3, r4]


if __name__ == "__main__":
    p = int(input("Enter p (p mod 4 = 3): "))
    q = int(input("Enter q (q mod 4 = 3): "))
    m = int(input("Enter plaintext integer m: "))

    n = p * q
    if not 0 <= m < n:
        print("m must satisfy 0 <= m < n.")
    else:
        c = encrypt(m, n)
        roots = decrypt(c, p, q)

        print("Public key n:", n)
        print("Ciphertext:", c)
        print("Four possible plaintext roots:", roots)
        print("Original m found:", m in roots)
