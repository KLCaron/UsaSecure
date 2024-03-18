import getpass
import math
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


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
    # we're assuming the attacker can try 10^12 passwords a second.
    bft_seconds = 2 ** entropy / (10 ** 12)

    time_units = [
        ("years", 12 * 30 * 24 * 60 * 60),
        ("months", 30 * 24 * 60 * 60),
        ("weeks", 7 * 24 * 60 * 60),
        ("days", 24 * 60 * 60),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1)
    ]

    for unit, multiplier in time_units:
        if bft_seconds >= multiplier:
            if multiplier <= 24 * 60 * 60:  # Less than or equal to 1 day
                return f"{RED}Weak{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}"
            elif multiplier <= 7 * 24 * 60 * 60:  # Less than or equal to 1 week
                return f"{YELLOW}Medium{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}"
            else:
                return f"{GREEN}Strong{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}"

    # If the estimated time is less than a second
    return f"{RED}Weak{RESET} - Less than a second"


def analyze_password(password):
    alphanumeracy, length, entropy = check_alphanumeracy(password), check_length(password), calculate_entropy(password)
    bft = estimate_bft(entropy)

    print(f"{'Contains only letters and numbers' if alphanumeracy else 'Contains more than just letters and numbers'}")
    print(f"Password Length: {length}")
    print(f"Entropy: {entropy:.2f} bits")
    print(f"Brute Force Time Estimate: {bft}")


def main():
    while True:
        password = get_password()
        analyze_password(password)
        choice = input("Check another password? (y/n): ")
        if choice.lower() != "y":
            break


if __name__ == "__main__":
    main()
