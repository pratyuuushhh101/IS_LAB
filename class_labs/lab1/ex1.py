def mod_inv(a,m):
    for i in range(1,m):
        if(a*i)%m==1:
            return i
    return None
pt="I am learning information security"
pt=pt.replace(" ","").lower()

def add_enc(text,key):
    cipher=""
    for ch in text:
        x=ord(ch)-ord('a')
        cipher+=chr(((x+key)%26)+ord('a'))
    return cipher
print(add_enc(pt,20))

def add_dec(cipher,key):
    text=""
    for ch in cipher:
        x=ord(ch)-ord('a')
        text+=chr(((x-key)%26)+ord('a'))
    return text

print(add_dec(add_enc(pt,20),20))

def mul_enc(text, key):
    cipher = ""
    for ch in text:
        x = ord(ch) - ord('a')
        cipher += chr(((x * key) % 26) + ord('a'))
    return cipher

def mul_dec(cipher, key):
    inv = mod_inv(key, 26)
    if inv is None:
        return "Key has no modular inverse."
    text = ""
    for ch in cipher:
        y = ord(ch) - ord('a')
        text += chr(((y * inv) % 26) + ord('a'))
    return text

print(mul_enc(pt,15))
print(mul_dec(mul_enc(pt,15),15))

def affine_enc(text, key_a, key_b):
    cipher = ""
    for ch in text:
        x = ord(ch) - ord('a')
        # E(x) = (a * x + b) mod 26
        cipher += chr((((x * key_a) + key_b) % 26) + ord('a'))
    return cipher

def affine_dec(cipher, key_a, key_b):
    inv = mod_inv(key_a, 26)
    if inv is None:
        return "Key has no modular inverse."
    text = ""
    for ch in cipher:
        y = ord(ch) - ord('a')
        # D(y) = a^-1 * (y - b) mod 26
        text += chr((((y - key_b) * inv) % 26) + ord('a'))
    return text

print(affine_enc(pt,15,20))
print(affine_dec(affine_enc(pt,15,20),15,20))