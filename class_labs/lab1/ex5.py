import string

a = string.ascii_lowercase

p = "yes"
c = "ciw"

s = (a.index(c[0]) - a.index(p[0])) % 26

x = "xviewywi"

r = ""
for i in x:
    r += a[(a.index(i) - s) % 26]

print("Known Plaintext Attack")
print(r)