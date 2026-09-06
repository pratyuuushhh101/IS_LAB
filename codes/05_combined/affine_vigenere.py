# Combined pipeline: plaintext -> Affine -> Vigenere -> ciphertext

from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "01_classical"))

from affine import encrypt as affine_encrypt, decrypt as affine_decrypt
from vigenere import encrypt as vig_encrypt, decrypt as vig_decrypt
from alphabet import ALPHABET_26


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    a = int(input("Affine a: "))
    b = int(input("Affine b: "))
    key = input("Vigenere key: ")

    stage1 = affine_encrypt(plaintext, a, b, ALPHABET_26)
    stage2 = vig_encrypt(stage1, key, ALPHABET_26)

    recovered_stage1 = vig_decrypt(stage2, key, ALPHABET_26)
    recovered = affine_decrypt(recovered_stage1, a, b, ALPHABET_26)

    print("\nAfter Affine:", stage1)
    print("Final ciphertext:", stage2)
    print("After reverse Vigenere:", recovered_stage1)
    print("Recovered plaintext:", recovered)
