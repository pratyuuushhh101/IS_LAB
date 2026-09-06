from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

receiver_private = ec.generate_private_key(ec.SECP256R1())
receiver_public = receiver_private.public_key()

shared_key = private_key.exchange(ec.ECDH(), receiver_public)

key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECC"
).derive(shared_key)

message = b"Secure Transactions"
nonce = os.urandom(12)

ciphertext = AESGCM(key).encrypt(nonce, message, None)

shared_key2 = receiver_private.exchange(ec.ECDH(), public_key)

key2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECC"
).derive(shared_key2)

plaintext = AESGCM(key2).decrypt(nonce, ciphertext, None)

print("Original:", message.decode())
print("Ciphertext:", ciphertext.hex())
print("Decrypted:", plaintext.decode())
