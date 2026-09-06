import secrets
import logging
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa

logging.basicConfig(
    filename="kms.log",
    level=logging.INFO
)

class Rabin:
    def prime(self, bits):
        while True:
            n = secrets.randbits(bits) | (1 << bits-1) | 3
            for i in range(2, 1000):
                if n % i == 0 and n != i:
                    break
            else:
                return n

    def generate(self, bits=1024):
        p = self.prime(bits // 2)
        q = self.prime(bits // 2)
        return p*q, (p, q)

    def encrypt(self, m, n):
        x = int.from_bytes(m.encode(), "big")
        return pow(x, 2, n)

    def decrypt(self, c, key):
        p, q = key
        n = p*q
        mp = pow(c, (p+1)//4, p)
        mq = pow(c, (q+1)//4, q)

        _, yp, yq = self.egcd(p, q)

        r1 = (yp*p*mq + yq*q*mp) % n
        r2 = n-r1
        r3 = (yp*p*mq - yq*q*mp) % n
        r4 = n-r3

        return [r1, r2, r3, r4]

    def egcd(self, a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = self.egcd(b, a % b)
        return g, y, x-(a//b)*y


class KMS:
    def __init__(self, bits=1024):
        self.bits = bits
        self.data = {}
        self.rabin = Rabin()

    def register(self, name):
        public, private = self.rabin.generate(self.bits)

        self.data[name] = {
            "public": public,
            "private": private,
            "created": datetime.now(),
            "expiry": datetime.now() + timedelta(days=365),
            "revoked": False
        }

        logging.info("Generated key for %s", name)

    def public_key(self, name):
        if self.data[name]["revoked"]:
            raise Exception("Key revoked")
        return self.data[name]["public"]

    def revoke(self, name):
        self.data[name]["revoked"] = True
        logging.info("Revoked key for %s", name)

    def renew(self, name):
        self.register(name)
        logging.info("Renewed key for %s", name)


kms = KMS(1024)

kms.register("Hospital_A")
kms.register("Hospital_B")
kms.register("Clinic_A")

n = kms.public_key("Hospital_A")

message = "PatientRecord"
cipher = kms.rabin.encrypt(message, n)

print("Ciphertext:", cipher)

roots = kms.rabin.decrypt(
    cipher,
    kms.data["Hospital_A"]["private"]
)

print("Possible roots:", roots)

kms.revoke("Clinic_A")
kms.renew("Hospital_B")

print("KMS completed")