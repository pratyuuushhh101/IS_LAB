import secrets
import time

p = 23
g = 5

start = time.perf_counter()

a = secrets.randbelow(p - 2) + 1
b = secrets.randbelow(p - 2) + 1

A = pow(g, a, p)
B = pow(g, b, p)

key1 = pow(B, a, p)
key2 = pow(A, b, p)

time_taken = time.perf_counter() - start

print("Peer A Private Key:", a)
print("Peer A Public Key:", A)

print("Peer B Private Key:", b)
print("Peer B Public Key:", B)

print("Peer A Shared Secret:", key1)
print("Peer B Shared Secret:", key2)

print("Keys Match:", key1 == key2)
print("Key Exchange Time:", time_taken)
