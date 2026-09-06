ALPHABET_26 = "abcdefghijklmnopqrstuvwxyz"
ALPHABET_62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


# Parameters: alphabet (str) -> Output: None
def validate_alphabet(alphabet):
    if not alphabet:
        raise ValueError("Alphabet cannot be empty.")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("Alphabet characters must be unique.")


# Parameters: ch (str), alphabet (str) -> Output: int
def char_to_num(ch, alphabet):
    return alphabet.index(ch)


# Parameters: num (int), alphabet (str) -> Output: str
def num_to_char(num, alphabet):
    return alphabet[num % len(alphabet)]


# Parameters: text (str), alphabet (str), preserve_unknown (bool) -> Output: str
def clean_text(text, alphabet, preserve_unknown=True):
    if preserve_unknown:
        return "".join(ch for ch in text if ch in alphabet or ch.isspace())
    return "".join(ch for ch in text if ch in alphabet)


# Parameters: None -> Output: str
def choose_alphabet():
    print("\nChoose alphabet:")
    print("1. 26-character lowercase alphabet")
    print("2. 62-character alphabet: a-z A-Z 0-9")
    print("3. Custom alphabet")

    choice = input("Choice: ").strip()

    if choice == "1":
        return ALPHABET_26
    if choice == "2":
        return ALPHABET_62
    if choice == "3":
        alphabet = input("Enter custom alphabet: ")
        validate_alphabet(alphabet)
        return alphabet

    raise ValueError("Invalid alphabet choice.")
