# Pipeline:
# plaintext -> Playfair -> DES
# DES key -> ElGamal
#
# This is an educational hybrid template.
# ElGamal encrypts the DES key as an integer, so p must be larger
# than the integer representation of the 8-byte DES key.

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "01_classical"))
from playfair import encrypt as playfair_encrypt, decrypt as playfair_decrypt


# Parameters: m (int), p (int), g (int), y (int), k (int) -> Output: tuple[int, int]
def elgamal_encrypt(m, p, g, y, k):
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    return c1, c2


# Parameters: c1 (int), c2 (int), p (int), x (int) -> Output: int
def elgamal_decrypt(c1, c2, p, x):
    s = pow(c1, x, p)
    return (c2 * pow(s, -1, p)) % p


def main():
    plaintext = input("Plaintext: ")
    playfair_key = input("Playfair keyword: ")
    des_key = input("DES key (8 ASCII chars): ")

    if len(des_key.encode()) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    p = int(input("ElGamal prime p: "))
    g = int(input("ElGamal generator g: "))
    x = int(input("ElGamal private key x: "))
    k = int(input("ElGamal random k: "))

    y = pow(g, x, p)

    # Stage 1
    playfair_cipher, matrix = playfair_encrypt(plaintext, playfair_key)

    # Stage 2
    iv = b"12345678"
    des = DES.new(des_key.encode(), DES.MODE_CBC, iv)
    des_cipher = des.encrypt(pad(playfair_cipher.encode(), 8))
    des_b64 = base64.b64encode(des_cipher).decode()

    # Stage 3: ElGamal-encrypt DES key.
    key_int = int.from_bytes(des_key.encode(), "big")
    if key_int >= p:
        raise ValueError("ElGamal p must be larger than DES-key integer.")

    c1, c2 = elgamal_encrypt(key_int, p, g, y, k)

    # Reverse Stage 3
    recovered_key_int = elgamal_decrypt(c1, c2, p, x)
    recovered_des_key = recovered_key_int.to_bytes(8, "big")

    # Reverse Stage 2
    decipher = DES.new(recovered_des_key, DES.MODE_CBC, iv)
    recovered_playfair = unpad(
        decipher.decrypt(base64.b64decode(des_b64)), 8
    ).decode()

    # Reverse Stage 1
    recovered_plaintext, _ = playfair_decrypt(
        recovered_playfair, playfair_key
    )

    print("\n===== PLAYFAIR =====")
    for row in matrix:
        print(" ".join(row))
    print("Playfair ciphertext:", playfair_cipher)

    print("\n===== DES =====")
    print("IV:", iv.decode())
    print("DES ciphertext (Base64):", des_b64)

    print("\n===== ELGAMAL =====")
    print("Public key:", (p, g, y))
    print("ElGamal encrypted DES key:", (c1, c2))
    print("Recovered DES key:", recovered_des_key.decode())

    print("\n===== FINAL =====")
    print("Recovered plaintext:", recovered_plaintext)
    print("Verification:",
          recovered_plaintext.replace(" ", "").upper().replace("J", "I")
          == "".join(
              "".join(playfair_decrypt(
                  playfair_cipher, playfair_key
              )[0]).split()
          ).replace("J", "I"))


if __name__ == "__main__":
    main()
