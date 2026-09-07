# from Crypto.Cipher import DES
# from Crypto.Util.Padding import pad, unpad
# import base64


# # Parameters: plaintext (str), key (str) -> Output: str (Base64)
# def encrypt(plaintext, key):
#     key = key.encode()
#     if len(key) != 8:
#         raise ValueError("DES key must be exactly 8 bytes.")

#     cipher = DES.new(key, DES.MODE_ECB)
#     ciphertext = cipher.encrypt(pad(plaintext.encode(), 8))
#     return base64.b64encode(ciphertext).decode()


# # Parameters: ciphertext_b64 (str), key (str) -> Output: str
# def decrypt(ciphertext_b64, key):
#     key = key.encode()
#     cipher = DES.new(key, DES.MODE_ECB)
#     ciphertext = base64.b64decode(ciphertext_b64)
#     return unpad(cipher.decrypt(ciphertext), 8).decode()


# if __name__ == "__main__":
#     plaintext = input("Enter plaintext: ")
#     key = input("Enter DES key (8 characters): ")

#     try:
#         ciphertext = encrypt(plaintext, key)
#         recovered = decrypt(ciphertext, key)

#         print("\nDES ciphertext (Base64):", ciphertext)
#         print("Decrypted:", recovered)
#         print("Verification:", recovered == plaintext)
#     except Exception as e:
#         print("Error:", e)


from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64


# ---------------------------------------------------------
# CUSTOM PADDING
# ---------------------------------------------------------

def custom_pad(data, block_size=8, pad_char="X"):
    """
    Pads data with pad_char until its length is
    a multiple of block_size.
    """
    padding_length = (-len(data)) % block_size

    if padding_length == 0:
        return data

    return data + pad_char * padding_length


def custom_unpad(data, pad_char="X"):
    """
    Removes custom padding.
    The last character tells us what padding was used.
    """
    if not data:
        return data

    i = len(data) - 1

    while i >= 0 and data[i] == pad_char:
        i -= 1

    return data[:i + 1]


# ---------------------------------------------------------
# DES ENCRYPTION
# ---------------------------------------------------------

def encrypt(plaintext, key, padding_type="standard", pad_char="X"):

    key = key.encode()

    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    plaintext_bytes = plaintext.encode()

    # Choose padding
    if padding_type == "standard":
        plaintext_bytes = pad(plaintext_bytes, 8)

    elif padding_type == "custom":
        plaintext_bytes = custom_pad(
            plaintext_bytes,
            8,
            pad_char
        ).encode()

    else:
        raise ValueError("Padding type must be 'standard' or 'custom'.")

    # DES ECB
    cipher = DES.new(key, DES.MODE_ECB)

    ciphertext = cipher.encrypt(plaintext_bytes)

    # Convert binary ciphertext to Base64
    return base64.b64encode(ciphertext).decode()


# ---------------------------------------------------------
# DES DECRYPTION
# ---------------------------------------------------------

def decrypt(ciphertext_b64, key, padding_type="standard", pad_char="X"):

    key = key.encode()

    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    # Convert Base64 back to bytes
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = DES.new(key, DES.MODE_ECB)

    decrypted = cipher.decrypt(ciphertext)

    # Remove padding
    if padding_type == "standard":
        plaintext = unpad(decrypted, 8)

    elif padding_type == "custom":
        plaintext = custom_unpad(
            decrypted.decode(),
            pad_char
        ).encode()

    else:
        raise ValueError("Padding type must be 'standard' or 'custom'.")

    return plaintext.decode()


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    plaintext = input("Enter plaintext: ")
    key = input("Enter DES key (8 characters): ")

    print("\nChoose padding:")
    print("1. Standard PKCS#7")
    print("2. Custom padding")

    choice = input("Enter choice: ")

    try:

        if choice == "1":

            ciphertext = encrypt(
                plaintext,
                key,
                padding_type="standard"
            )

            recovered = decrypt(
                ciphertext,
                key,
                padding_type="standard"
            )

        elif choice == "2":

            pad_char = input(
                "Enter padding character: "
            )

            if len(pad_char) != 1:
                raise ValueError(
                    "Padding character must be exactly one character."
                )

            ciphertext = encrypt(
                plaintext,
                key,
                padding_type="custom",
                pad_char=pad_char
            )

            recovered = decrypt(
                ciphertext,
                key,
                padding_type="custom",
                pad_char=pad_char
            )

        else:
            raise ValueError("Invalid choice.")

        print("\nDES ciphertext (Base64):", ciphertext)
        print("Decrypted:", recovered)
        print("Verification:", recovered == plaintext)

    except Exception as e:
        print("Error:", e)