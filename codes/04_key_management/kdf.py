import hashlib
import os


def derive_key(password, salt, iterations=100000, length=32):
    password = password.encode()
    return hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        iterations,
        dklen=length
    )


if __name__ == "__main__":
    password = input("Enter password: ")
    iterations = int(input("Iterations: "))

    salt = os.urandom(16)
    key = derive_key(password, salt, iterations)

    print("Salt:", salt.hex())
    print("Derived key:", key.hex())
