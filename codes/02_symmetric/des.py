from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64


# Parameters: plaintext (str), key (str) -> Output: str (Base64)
def encrypt(plaintext, key):
    key = key.encode()
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), 8))
    return base64.b64encode(ciphertext).decode()


# Parameters: ciphertext_b64 (str), key (str) -> Output: str
def decrypt(ciphertext_b64, key):
    key = key.encode()
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    return unpad(cipher.decrypt(ciphertext), 8).decode()


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    key = input("Enter DES key (8 characters): ")

    try:
        ciphertext = encrypt(plaintext, key)
        recovered = decrypt(ciphertext, key)

        print("\nDES ciphertext (Base64):", ciphertext)
        print("Decrypted:", recovered)
        print("Verification:", recovered == plaintext)
    except Exception as e:
        print("Error:", e)
