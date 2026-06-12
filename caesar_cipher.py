def encrypt(text, shift):
    encrypted_text = ""

    for char in text:
        # Encrypt uppercase letters
        if char.isupper():
            base = ord('A')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            encrypted_text += encrypted_char

        # Encrypt lowercase letters
        elif char.islower():
            base = ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            encrypted_text += encrypted_char

        # Keep spaces, numbers, and punctuation unchanged
        else:
            encrypted_text += char

    return encrypted_text


def decrypt(text, shift):
    decrypted_text = ""

    for char in text:
        # Decrypt uppercase letters
        if char.isupper():
            base = ord('A')
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            decrypted_text += decrypted_char

        # Decrypt lowercase letters
        elif char.islower():
            base = ord('a')
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            decrypted_text += decrypted_char

        # Keep spaces, numbers, and punctuation unchanged
        else:
            decrypted_text += char

    return decrypted_text


def get_shift_key():
    try:
        shift = int(input("Enter shift key: "))
        return shift
    except ValueError:
        print("Invalid shift key. Please enter a number.")
        return None


def main():
    print("=== Basic Encryption & Decryption: Caesar Cipher ===")
    print("Choose an option:")
    print("1. Encrypt text")
    print("2. Decrypt text")
    print("3. Encrypt then decrypt for validation")

    choice = input("Enter your choice (1/2/3): ")

    if choice not in ["1", "2", "3"]:
        print("Invalid choice. Please choose 1, 2, or 3.")
        return

    text = input("Enter your text: ")

    shift = get_shift_key()
    if shift is None:
        return

    if choice == "1":
        encrypted = encrypt(text, shift)

        print("\nOriginal Text:", text)
        print("Encrypted Text:", encrypted)

    elif choice == "2":
        decrypted = decrypt(text, shift)

        print("\nEncrypted Text:", text)
        print("Decrypted Text:", decrypted)

    elif choice == "3":
        encrypted = encrypt(text, shift)
        decrypted = decrypt(encrypted, shift)

        print("\nOriginal Text:", text)
        print("Encrypted Text:", encrypted)
        print("Decrypted Text:", decrypted)

        if decrypted == text:
            print("\nValidation: Success. Decryption returned the original text.")
        else:
            print("\nValidation: Failed. Decryption did not match the original text.")


if __name__ == "__main__":
    main()