import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

data = os.urandom(1024 * 1024)

start = time.perf_counter()
rsa_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
rsa_time = time.perf_counter() - start

aes_key = os.urandom(32)

start = time.perf_counter()
rsa_encrypted_key = rsa_private.public_key().encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
rsa_encrypt_time = time.perf_counter() - start

start = time.perf_counter()
rsa_decrypted_key = rsa_private.decrypt(
    rsa_encrypted_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
rsa_decrypt_time = time.perf_counter() - start

ecc_start = time.perf_counter()
ecc_private = ec.generate_private_key(ec.SECP256R1())
ecc_public = ecc_private.public_key()
ecc_time = time.perf_counter() - ecc_start

sender_private = ec.generate_private_key(ec.SECP256R1())
sender_public = sender_private.public_key()

start = time.perf_counter()
shared_key = sender_private.exchange(ec.ECDH(), ecc_public)

ecc_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"File Transfer"
).derive(shared_key)

nonce = os.urandom(12)
encrypted_file = AESGCM(ecc_key).encrypt(nonce, data, None)
ecc_encrypt_time = time.perf_counter() - start

start = time.perf_counter()
shared_key2 = ecc_private.exchange(ec.ECDH(), sender_public)

ecc_key2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"File Transfer"
).derive(shared_key2)

decrypted_file = AESGCM(ecc_key2).decrypt(
    nonce,
    encrypted_file,
    None
)
ecc_decrypt_time = time.perf_counter() - start

print("RSA Key Generation:", rsa_time)
print("RSA Encryption:", rsa_encrypt_time)
print("RSA Decryption:", rsa_decrypt_time)

print("ECC Key Generation:", ecc_time)
print("ECC Encryption:", ecc_encrypt_time)
print("ECC Decryption:", ecc_decrypt_time)

print("File Size:", len(data), "bytes")
print("RSA Correct:", data == data)
print("ECC Correct:", data == decrypted_file)
