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
        for unit, multiplier in time_units:
            if bft_seconds >= multiplier:
                if multiplier <= 24 * 60 * 60:  # Less than or equal to 1 day
                    results.append(f"{RED}Weak{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}")
                elif multiplier <= 7 * 24 * 60 * 60:  # Less than or equal to 1 week
                    results.append(f"{YELLOW}Medium{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}")
                else:
                    results.append(f"{GREEN}Strong{RESET} - Approximately {int(bft_seconds // multiplier)} {unit}")

                break

    # If the estimated time is less than a second
    results.append(f"{RED}Weak{RESET} - Less than a second")

    return results


def analyze_password(password):
    alphanumeracy, length, entropy = check_alphanumeracy(password), check_length(password), calculate_entropy(password)
    bft_results = estimate_bft(entropy)

    print(f"{'Contains only letters and numbers' if alphanumeracy else 'Contains more than just letters and numbers'}")
    print(f"Password Length: {length}")
    print(f"Entropy: {entropy:.2f} bits")
    print("Lower End Estimate:")
    print(f"Brute Force Time Estimate: {bft_results[0]}")
    print("Higher End Estimate:")
    print(f"Brute Force Time Estimate: {bft_results[1]}")


def main():
    while True:
        password = get_password()
        analyze_password(password)
        choice = input("Check another password? (y/n): ")
        if choice.lower() != "y":
            break


if __name__ == "__main__":
    main()
