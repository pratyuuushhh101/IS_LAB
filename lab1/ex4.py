import string

a = string.ascii_lowercase
k = [[3, 3], [2, 7]]

t = "".join(i.lower() for i in "We live in an insecure world" if i.isalpha())

if len(t) % 2:
    t += "x"

r = ""

for i in range(0, len(t), 2):
    x = a.index(t[i])
    y = a.index(t[i + 1])
    r += a[(3 * x + 3 * y) % 26]
    r += a[(2 * x + 7 * y) % 26]

print(r)