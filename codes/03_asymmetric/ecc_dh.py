from cryptography.hazmat.primitives.asymmetric import ec


def main():
    print("ECC demonstration: Elliptic Curve Diffie-Hellman")
    print("This follows the manual's treatment of ECC as primarily key exchange.")

    private_a = ec.generate_private_key(ec.SECP256R1())
    private_b = ec.generate_private_key(ec.SECP256R1())

    public_a = private_a.public_key()
    public_b = private_b.public_key()

    shared_a = private_a.exchange(ec.ECDH(), public_b)
    shared_b = private_b.exchange(ec.ECDH(), public_a)

    print("Alice public key generated.")
    print("Bob public key generated.")
    print("Shared secret (hex):", shared_a.hex())
    print("Verification:", shared_a == shared_b)


if __name__ == "__main__":
    main()
