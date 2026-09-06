import secrets


# Parameters: p (int) -> Output: int
def generate_private_key(p):
    return secrets.randbelow(p - 2) + 1


# Parameters: g (int), private (int), p (int) -> Output: int
def public_key(g, private, p):
    return pow(g, private, p)


# Parameters: other_public (int), private (int), p (int) -> Output: int
def shared_secret(other_public, private, p):
    return pow(other_public, private, p)


if __name__ == "__main__":
    p = int(input("Enter prime p: "))
    g = int(input("Enter generator g: "))

    a = generate_private_key(p)
    b = generate_private_key(p)

    A = public_key(g, a, p)
    B = public_key(g, b, p)

    secret_a = shared_secret(B, a, p)
    secret_b = shared_secret(A, b, p)

    print("\nAlice private key:", a)
    print("Alice public key:", A)
    print("Bob private key:", b)
    print("Bob public key:", B)
    print("Alice shared secret:", secret_a)
    print("Bob shared secret:", secret_b)
    print("Verification:", secret_a == secret_b)
