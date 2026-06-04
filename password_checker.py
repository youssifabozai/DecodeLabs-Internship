import string
import getpass


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou"
}


def check_password_strength(password):
    score = 0
    feedback = []

    # 1. Critical length check
    # Any password shorter than 8 characters is automatically weak.
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
        feedback.append("Passwords shorter than 8 characters are considered weak.")
        return "Weak", score, feedback

    # 2. Length scoring
    score += 1

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Use 12 or more characters for better security.")

    # 3. Lowercase check
    has_lowercase = any(char.islower() for char in password)
    if has_lowercase:
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # 4. Uppercase check
    has_uppercase = any(char.isupper() for char in password)
    if has_uppercase:
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # 5. Digit check
    has_digit = any(char.isdigit() for char in password)
    if has_digit:
        score += 1
    else:
        feedback.append("Add numbers.")

    # 6. Symbol check
    has_symbol = any(char in string.punctuation for char in password)
    if has_symbol:
        score += 1
    else:
        feedback.append("Add symbols like @, #, $, %, or !.")

    # 7. Common password check
    if password.lower() not in COMMON_PASSWORDS:
        score += 1
    else:
        feedback.append("Do not use common or leaked passwords.")

    # Final classification
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, score, feedback


def main():
    print("=== Password Strength Checker ===")

    # This hides the password while typing
    password = getpass.getpass("Enter your password: ")

    strength, score, feedback = check_password_strength(password)

    print("\nPassword Strength:", strength)
    print("Score:", score, "/ 7")

    if feedback:
        print("\nSuggestions:")
        for item in feedback:
            print("-", item)
    else:
        print("\nGreat password structure!")


if __name__ == "__main__":
    main()