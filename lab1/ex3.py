def create_playfair_matrix(keyword):
    # Remove duplicates from keyword and handle I/J
    processed_key = ""
    for ch in keyword.lower():
        if ch == 'j':
            ch = 'i'
        if ch not in processed_key and ch.isalpha():
            processed_key += ch

    # Fill the rest of the alphabet (excluding 'j')
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    matrix_chars = processed_key
    for ch in alphabet:
        if ch not in matrix_chars:
            matrix_chars += ch

    # Create 5x5 grid
    matrix = [list(matrix_chars[i:i + 5]) for i in range(0, 25, 5)]
    return matrix


def find_position(matrix, ch):
    if ch == 'j':
        ch = 'i'
    for r_idx, row in enumerate(matrix):
        if ch in row:
            return r_idx, row.index(ch)
    return None


def prepare_plaintext(text):
    text = text.replace(" ", "").lower().replace('j', 'i')
    digrams = []
    i = 0
    while i < len(text):
        char1 = text[i]
        if i + 1 < len(text):
            char2 = text[i + 1]
            if char1 == char2:
                digrams.append(char1 + 'x')
                i += 1
            else:
                digrams.append(char1 + char2)
                i += 2
        else:
            digrams.append(char1 + 'x')
            i += 1
    return digrams


def playfair_encrypt(text, matrix):
    digrams = prepare_plaintext(text)
    ciphertext = ""
    for digram in digrams:
        r1, c1 = find_position(matrix, digram[0])
        r2, c2 = find_position(matrix, digram[1])

        if r1 == r2:
            # Same row, shift right
            ciphertext += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            # Same column, shift down
            ciphertext += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:
            # Rectangle, swap columns
            ciphertext += matrix[r1][c2] + matrix[r2][c1]

    return ciphertext


# Main execution
keyword = "guidance"
message = "The key is hidden under the door pad"

matrix = create_playfair_matrix(keyword)
encrypted_msg = playfair_encrypt(message, matrix)

print("--- Playfair Cipher ---")
print("Matrix:")
for row in matrix:
    print(" ".join(row))
print("\nEncrypted:", encrypted_msg)