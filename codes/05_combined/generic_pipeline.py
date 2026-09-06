# Generic conceptual pipeline.
# Add stages in the order required by the question.
# Decryption MUST apply stages in reverse order.

def apply_pipeline(data, stages):
    for name, function in stages:
        data = function(data)
        print(f"After {name}: {data}")
    return data


def apply_reverse_pipeline(data, stages):
    for name, function in reversed(stages):
        data = function(data)
        print(f"After reversing {name}: {data}")
    return data


if __name__ == "__main__":
    # Demo with simple functions.
    stages = [
        ("Uppercase", lambda x: x.upper()),
        ("Reverse", lambda x: x[::-1]),
    ]

    plaintext = input("Enter plaintext: ")

    print("\n===== ENCRYPTION =====")
    ciphertext = apply_pipeline(plaintext, stages)
    print("Final ciphertext:", ciphertext)

    reverse_stages = [
        ("Reverse", lambda x: x[::-1]),
        ("Uppercase reverse", lambda x: x.lower()),
    ]

    print("\n===== DECRYPTION =====")
    recovered = apply_reverse_pipeline(ciphertext, reverse_stages)
    print("Recovered:", recovered)
