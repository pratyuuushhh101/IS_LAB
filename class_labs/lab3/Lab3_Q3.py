import secrets

p = 1461501637330902918203684832716283019655932542983
g = 2

x = secrets.randbelow(p - 2) + 1
h = pow(g, x, p)

message = b"Confidential Data"
m = int.from_bytes(message, "big")

k = secrets.randbelow(p - 2) + 1

c1 = pow(g, k, p)
c2 = (m * pow(h, k, p)) % p

s = pow(c1, x, p)
m2 = (c2 * pow(s, -1, p)) % p

plaintext = m2.to_bytes((m2.bit_length() + 7) // 8, "big")

print("Original:", message.decode())
print("Public Key:", (p, g, h))
print("Private Key:", x)
print("Ciphertext:", (c1, c2))
print("Decrypted:", plaintext.decode())
