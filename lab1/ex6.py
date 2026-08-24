import string
from math import gcd

alphabet = string.ascii_lowercase
c = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS".lower()


def mod_inv(x):
    for i in range(26):
        if (x * i) % 26 == 1:
            return i
    return None


# Known plaintext-ciphertext pairs: 'a' -> 'g', 'b' -> 'l'
# x1 = 0, y1 = 6 ('g')
# x2 = 1, y2 = 11 ('l')

x1, y1 = 0, ord('g') - ord('a')
x2, y2 = 1, ord('l') - ord('a')

# Brute-force checking all possible keys a and b
found = False
for a in range(1, 26):
    if gcd(a, 26) != 1:
        continue
    for b in range(26):
        # Check if this key pair satisfies the known pairs
        if (a * x1 + b) % 26 == y1 and (a * x2 + b) % 26 == y2:
            print(f"Found keys -> a: {a}, b: {b}")

            # Decryption
            inv_a = mod_inv(a)
            plaintext = ""
            for ch in c:
                y = ord(ch) - ord('a')
                # D(y) = a^-1 * (y - b) mod 26
                orig_char = alphabet[(inv_a * (y - b)) % 26]
                plaintext += orig_char

            print("Decrypted Message:", plaintext)
            found = True
            break
    if found:
        break