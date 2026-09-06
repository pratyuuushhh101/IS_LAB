from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, os

class KMS:
    def __init__(self):
        self.keys = {}
        self.revoked = set()

    def register(self, name):
        p = rsa.generate_private_key(65537, 2048)
        self.keys[name] = (p, p.public_key())

    def public_key(self, name):
        if name in self.revoked:
            raise Exception("Key revoked")
        return self.keys[name][1]

    def revoke(self, name):
        self.revoked.add(name)

    def renew(self, name):
        self.register(name)

params = dh.generate_parameters(generator=2, key_size=2048)

kms = KMS()
kms.register("Finance")
kms.register("HR")
kms.register("SupplyChain")

finance_dh = params.generate_private_key()
hr_dh = params.generate_private_key()

k1 = hashlib.sha256(
    finance_dh.exchange(hr_dh.public_key())
).digest()

k2 = hashlib.sha256(
    hr_dh.exchange(finance_dh.public_key())
).digest()

print("DH keys match:", k1 == k2)

msg = b"Confidential Financial Report"

aes = AESGCM(k1)
nonce = os.urandom(12)
cipher = aes.encrypt(nonce, msg, None)

plain = aes.decrypt(nonce, cipher, None)
print("Decrypted:", plain.decode())

private = kms.keys["Finance"][0]

signature = private.sign(
    msg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

kms.public_key("Finance").verify(
    signature,
    msg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("Signature verified")

kms.revoke("SupplyChain")
kms.renew("HR")

print("Key management completed")