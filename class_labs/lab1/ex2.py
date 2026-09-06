pt = "the house is being sold tonight"
pt = pt.replace(" ", "").lower()


def vigenere_enc(text, key):
    cipher = ""
    key = key.lower()
    key_length = len(key)
    for i, ch in enumerate(text):
        x = ord(ch) - ord('a')
        k = ord(key[i % key_length]) - ord('a')
        cipher += chr(((x + k) % 26) + ord('a'))
    return cipher


def vigenere_dec(cipher, key):
    text = ""
    key = key.lower()
    key_length = len(key)
    for i, ch in enumerate(cipher):
        x = ord(ch) - ord('a')
        k = ord(key[i % key_length]) - ord('a')
        text += chr(((x - k) % 26) + ord('a'))
    return text


vig_key = "dollars"
vig_cipher = vigenere_enc(pt, vig_key)
print("---Vigenère Cipher (Key: 'dollars') ---")
print("Encrypted:", vig_cipher)
print("Decrypted:", vigenere_dec(vig_cipher, vig_key))
print()


def autokey_enc(text, initial_key):
    cipher = ""
    stream = [initial_key] + [ord(c) - ord('a') for c in text[:-1]]

    for i, ch in enumerate(text):
        x = ord(ch) - ord('a')
        k = stream[i]
        cipher += chr(((x + k) % 26) + ord('a'))
    return cipher


def autokey_dec(cipher, initial_key):
    text = ""
    current_key = initial_key
    for i, ch in enumerate(cipher):
        y = ord(ch) - ord('a')
        x = (y - current_key) % 26
        dec_char = chr(x + ord('a'))
        text += dec_char
        # The next key is the decrypted plaintext character
        current_key = x
    return text


auto_key = 7  # Numeric shift key
auto_cipher = autokey_enc(pt, auto_key)
print("--- Autokey Cipher (Key: 7) ---")
print("Encrypted:", auto_cipher)
print("Decrypted:", autokey_dec(auto_cipher, auto_key))