import getpass
import math
from substitutions import CHARACTER_SUBSTITUTIONS

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def load_dictionary():
    with open("rockyou.txt", "r", encoding="latin-1") as file:
        passwords = file.read().splitlines()
    return passwords


DICTIONARY = load_dictionary()


def get_password():
    while True:
        hidden = input("Would you like to hide your password input? (y/n): ")
        if hidden.lower() == "y":
            password = getpass.getpass("Enter your potential password: ")
        else:
            password = input("Enter your potential password: ")
        if len(password) == 0:
            print("Password cannot be empty. Please enter a password")
        else:
            return password


def check_alphanumeracy(password):
    alphanumeracy = password.isalnum()
    return alphanumeracy


def check_length(password):
    length = len(password)
    return length


def calculate_entropy(password):
    unique_characters = len(set(password))
    entropy = math.log2(unique_characters) * len(password)
    return entropy


def estimate_bft(entropy):
    # Assuming the attacker can try between 2.5 billion to 100 billion passwords a second.
    bft_seconds_lower = 2 ** entropy / (2.5 * 10 ** 9)  # Lower end: 2.5 billion attempts per second
    bft_seconds_upper = 2 ** entropy / (1 * 10 ** 11)  # Upper end: 100 billion attempts per second

    time_units = [
        ("year(s)", 12 * 30 * 24 * 60 * 60),
        ("month(s)", 30 * 24 * 60 * 60),
        ("week(s)", 7 * 24 * 60 * 60),
        ("day(s)", 24 * 60 * 60),
        ("hour(s)", 60 * 60),
        ("minute(s)", 60),
        ("second(s)", 1)
    ]

    results = []

    for bft_seconds in [bft_seconds_lower, bft_seconds_upper]:
        if bft_seconds < 1:
            results.append(f"{RED}Weak{RESET} - Less than a second")
        else:
            for unit, multiplier in time_units:
                if bft_seconds >= multiplier:
                    if multiplier <= 24 * 60 * 60:  # Less than or equal to 1 day
                        results.append(f"{RED}Weak{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}")
                    elif multiplier <= 7 * 24 * 60 * 60:  # Less than or equal to 1 week
                        results.append(f"{YELLOW}Medium{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}")
                    else:
                        results.append(f"{GREEN}Strong{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}")

                    break

    return results


def dictionary_attack(password):
    password_lower = password.lower()
    demunge_match = False

    # check for a direct match.
    if password in DICTIONARY:
        return 1

    # create de-munged version of the password
    password_lower_demunged = password_lower
    for char, replacement in CHARACTER_SUBSTITUTIONS.items():
        password_lower_demunged = password_lower_demunged.replace(char, replacement)

    # check for a substring match, and a de-munged substring match.
    for word in DICTIONARY:
        word_lower = word.lower()
        if len(word_lower) > 4:
            if word_lower in password_lower:
                return 2
            elif word_lower in password_lower_demunged:
                demunge_match = True

    if demunge_match:
        return 3

    # no substring, de-munge, or direct match found
    return 0


def analyze_password(password):
    alphanumeracy, length, entropy = check_alphanumeracy(password), check_length(password), calculate_entropy(password)
    bft_results = estimate_bft(entropy)
    dictionary_attack_result = dictionary_attack(password)

    print(
        f"\nPassword {'Contains only letters and numbers' if alphanumeracy else 'Contains more than just letters and numbers'}",
        f"\nPassword Length: {length}",
        f"\nEntropy: {entropy:.2f} bits",
        "\nBrute Force Time:",
        f"\nLower End Estimate: {bft_results[0]}",
        f"\nHigher End Estimate: {bft_results[1]}",
        )
    print("Dictionary Attack: ", end='')
    if dictionary_attack_result == 1:
        print("Vulnerable")
    elif dictionary_attack_result == 2:
        print("Somewhat Vulnerable")
    elif dictionary_attack_result == 3:
        print("Distantly Vulnerable")
    else:
        print("Not Vulnerable")


def main():
    while True:
        password = get_password()

        analyze_password(password)
        choice = input("\nCheck another password? (y/n): ")
        if choice.lower() != "y":
            break


if __name__ == "__main__":
    main()
