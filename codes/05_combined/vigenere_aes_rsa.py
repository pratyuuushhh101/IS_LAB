# Pipeline:
# plaintext -> Vigenere -> AES
# AES key -> RSA
#
# Reverse:
# RSA -> recover AES key
# AES -> recover Vigenere ciphertext
# Vigenere -> plaintext

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "01_classical"))

from vigenere import encrypt as vig_encrypt, decrypt as vig_decrypt
from alphabet import ALPHABET_26


def rsa_encrypt_int(m, n, e):
    return pow(m, e, n)


def rsa_decrypt_int(c, n, d):
    return pow(c, d, n)


def main():
    plaintext = input("Plaintext: ")
    vig_key = input("Vigenere key: ")

    aes_key_text = input("AES key (16 ASCII chars): ")
    if len(aes_key_text.encode()) != 16:
        raise ValueError("This template uses a 16-byte AES key.")

    # Educational RSA parameters.
    p = int(input("RSA prime p: "))
    q = int(input("RSA prime q: "))
    e = int(input("RSA public exponent e: "))

    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    # Stage 1: Vigenere
    vig_cipher = vig_encrypt(plaintext, vig_key, ALPHABET_26)

    # Stage 2: AES-CBC with a fixed demo IV.
    # For an exam demonstration, printing the IV makes decryption reproducible.
    iv = b"1234567890ABCDEF"
    cipher = AES.new(aes_key_text.encode(), AES.MODE_CBC, iv)
    aes_cipher = cipher.encrypt(pad(vig_cipher.encode(), 16))
    aes_b64 = base64.b64encode(aes_cipher).decode()

    # Stage 3: RSA-encrypt AES key as an integer.
    aes_key_int = int.from_bytes(aes_key_text.encode(), "big")

    if aes_key_int >= n:
        raise ValueError("RSA modulus is too small for the AES key integer.")

    rsa_cipher = rsa_encrypt_int(aes_key_int, n, e)

    # Reverse RSA.
    recovered_key_int = rsa_decrypt_int(rsa_cipher, n, d)
    recovered_key = recovered_key_int.to_bytes(16, "big")

    # Reverse AES.
    decipher = AES.new(recovered_key, AES.MODE_CBC, iv)
    recovered_vig = unpad(
        decipher.decrypt(base64.b64decode(aes_b64)), 16
    ).decode()

    # Reverse Vigenere.
    recovered_plaintext = vig_decrypt(
        recovered_vig, vig_key, ALPHABET_26
    )

    print("\n===== ENCRYPTION =====")
    print("Vigenere ciphertext:", vig_cipher)
    print("AES IV:", iv.decode())
    print("AES ciphertext (Base64):", aes_b64)
    print("RSA encrypted AES key:", rsa_cipher)

    print("\n===== DECRYPTION =====")
    print("Recovered AES key:", recovered_key.decode())
    print("Recovered Vigenere ciphertext:", recovered_vig)
    print("Final plaintext:", recovered_plaintext)
    print("Verification:", recovered_plaintext == plaintext)


if __name__ == "__main__":
    main()
