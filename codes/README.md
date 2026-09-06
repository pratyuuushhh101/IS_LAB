# Information Security Lab Exam Code Pack

Each algorithm is a separate, copy-pasteable Python program.

Install:
    pip install pycryptodome numpy sympy cryptography

The manual requires interactive prompts, descriptive output, comments, and allows variations/combinations.
Classical ciphers use a configurable alphabet where practical.

Important:
- Standard Playfair is 5x5, so the supplied Playfair program uses A-Z with I/J combined.
- A 62-character alphabet cannot form a standard square Playfair matrix. Do not silently assume a 62-character Playfair variant.
- Hill cipher requires an invertible key matrix modulo the alphabet size.
- RSA/ElGamal/Rabin files are textbook educational implementations, not production cryptography.
- ECC is implemented as EC Diffie-Hellman/key agreement because the manual itself notes ECC is primarily used for key exchange rather than direct message encryption.
