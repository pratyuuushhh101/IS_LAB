import time
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad


# Parameters: None -> Output: None
def benchmark():
    text = "Performance Testing of Encryption Algorithms" * 1000

    des_key = b"A1B2C3D4"
    aes_key = b"0123456789ABCDEF0123456789ABCDEF"

    des = DES.new(des_key, DES.MODE_ECB)
    aes = AES.new(aes_key, AES.MODE_ECB)

    start = time.perf_counter()
    des.encrypt(pad(text.encode(), 8))
    des_time = time.perf_counter() - start

    start = time.perf_counter()
    aes.encrypt(pad(text.encode(), 16))
    aes_time = time.perf_counter() - start

    print(f"DES encryption time: {des_time:.8f} seconds")
    print(f"AES-256 encryption time: {aes_time:.8f} seconds")


if __name__ == "__main__":
    benchmark()
