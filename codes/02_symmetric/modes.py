from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import base64


def aes_cbc_encrypt(text, key, iv):
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    return base64.b64encode(
        cipher.encrypt(pad(text.encode(), AES.block_size))
    ).decode()


def aes_cbc_decrypt(ct, key, iv):
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    return unpad(
        cipher.decrypt(base64.b64decode(ct)),
        AES.block_size
    ).decode()


def aes_ctr_encrypt(text, key, nonce):
    cipher = AES.new(key.encode(), AES.MODE_CTR, nonce=nonce.encode())
    return base64.b64encode(cipher.encrypt(text.encode())).decode()


def aes_ctr_decrypt(ct, key, nonce):
    cipher = AES.new(key.encode(), AES.MODE_CTR, nonce=nonce.encode())
    return cipher.decrypt(base64.b64decode(ct)).decode()


def des_cbc_encrypt(text, key, iv):
    cipher = DES.new(key.encode(), DES.MODE_CBC, iv.encode())
    return base64.b64encode(cipher.encrypt(pad(text.encode(), 8))).decode()


def des_cbc_decrypt(ct, key, iv):
    cipher = DES.new(key.encode(), DES.MODE_CBC, iv.encode())
    return unpad(cipher.decrypt(base64.b64decode(ct)), 8).decode()


if __name__ == "__main__":
    print("1. AES-CBC")
    print("2. AES-CTR")
    print("3. DES-CBC")
    choice = input("Choice: ")

    text = input("Plaintext: ")

    if choice == "1":
        key = input("AES key (16/24/32 chars): ")
        iv = input("IV (16 chars): ")
        ct = aes_cbc_encrypt(text, key, iv)
        print("Ciphertext:", ct)
        print("Decrypted:", aes_cbc_decrypt(ct, key, iv))

    elif choice == "2":
        key = input("AES key (16/24/32 chars): ")
        nonce = input("Nonce (0-15 chars): ")
        ct = aes_ctr_encrypt(text, key, nonce)
        print("Ciphertext:", ct)
        print("Decrypted:", aes_ctr_decrypt(ct, key, nonce))

    elif choice == "3":
        key = input("DES key (8 chars): ")
        iv = input("IV (8 chars): ")
        ct = des_cbc_encrypt(text, key, iv)
        print("Ciphertext:", ct)
        print("Decrypted:", des_cbc_decrypt(ct, key, iv))

    else:
        print("Invalid choice.")
