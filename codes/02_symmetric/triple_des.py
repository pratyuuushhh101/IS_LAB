from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64


def encrypt(plaintext, key):
    key = key.encode()
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes.")

    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), 8))
    return base64.b64encode(ciphertext).decode()


def decrypt(ciphertext_b64, key):
    key = key.encode()
    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    return unpad(cipher.decrypt(ciphertext), 8).decode()


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    key = input("Enter 3DES key (16 or 24 characters): ")

    try:
        ciphertext = encrypt(plaintext, key)
        recovered = decrypt(ciphertext, key)

        print("\n3DES ciphertext (Base64):", ciphertext)
        print("Decrypted:", recovered)
        print("Verification:", recovered == plaintext)
    except Exception as e:
        print("Error:", e)
