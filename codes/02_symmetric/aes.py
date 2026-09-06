from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


# Parameters: plaintext (str), key (str) -> Output: str (Base64)
def encrypt(plaintext, key):
    key = key.encode()
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes.")

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(ciphertext).decode()


# Parameters: ciphertext_b64 (str), key (str) -> Output: str
def decrypt(ciphertext_b64, key):
    key = key.encode()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    key = input("Enter AES key (16/24/32 characters): ")

    try:
        ciphertext = encrypt(plaintext, key)
        recovered = decrypt(ciphertext, key)

        print("\nAES ciphertext (Base64):", ciphertext)
        print("Decrypted:", recovered)
        print("Verification:", recovered == plaintext)
    except Exception as e:
        print("Error:", e)
