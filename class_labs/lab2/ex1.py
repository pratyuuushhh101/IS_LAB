from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b"A1B2C3D4"
msg = b"Confidential Data"

cipher = DES.new(key, DES.MODE_ECB)
ct = cipher.encrypt(pad(msg, 8))
pt = unpad(cipher.decrypt(ct), 8)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())