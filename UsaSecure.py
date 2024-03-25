import getpass
import math
from substitutions import CHARACTER_SUBSTITUTIONS
from information import launch_information
# ANSI color codes for text formatting
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"
# Path to the password dictionary
DICTIONARY_SOURCE = "fortinet-2021_passwords.txt"


def load_dictionary():
    """
    Load the password dictionary from the specified file.

    :return: A list of passwords loaded from the file.
    :rtype: list[str]
    """
    with open(DICTIONARY_SOURCE, "r", encoding="latin-1") as file:
        # Read each line from the file and remove leading/trailing whitespaces
        passwords = [line.strip() for line in file]
    return passwords


# Load the dictionary of passwords
DICTIONARY = load_dictionary()


def get_password():
    """
    Prompt the user to enter a password and return it. User can also enter '?' to receive information on what this is.

    :return: The password entered by the user.
    :rtype: str
    """
    while True:
        hidden = input("Would you like to hide your password input? (y/n): ")
        if hidden.lower() == "y":
            password = getpass.getpass("Enter your potential password, or press '?' to find information on this app: ")
        else:
            password = input("Enter your potential password, or press '?' to find information on this app: ")
        if len(password) == 0:
            print("Password cannot be empty. Please enter a password")
        elif password.lower() == '?':
            launch_information()
        else:
            return password


def check_alphanumeracy(password):
    """
    Check if the given password contains only alphanumeric characters.

    :param str password: The password to be checked.
    :return: True if the password contains only alphanumeric characters, False otherwise.
    :rtype: bool
    """
    alphanumeracy = password.isalnum()
    return alphanumeracy


def check_length(password):
    """
    Calculate the length of the password.

    :param str password: The password to be checked.
    :return: The length of the password.
    :rtype: int
    """
    length = len(password)
    return length


def calculate_entropy(password):
    """
    Calculate the entropy of the given password.

    Entropy is a measure of password strength based on the number of unique characters it contains.

    :param str password: The password for which entropy needs to be calculated.
    :return: The entropy value of the password.
    :rtype: float
    """
    unique_characters = len(set(password))
    entropy = math.log2(unique_characters) * len(password)
    return entropy


def estimate_bft(entropy):
    """
    Estimate the time required for a brute-force attack to guess a password based on its entropy.

    Args:
    entropy (float): The entropy of the password.

    Returns:
    list[str]: A list of strings indicating the strength of the password and the estimated time for a brute-force
    attack to guess it.
    """
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
    """
    Perform a dictionary attack to check the strength of a password.

    Args:
    password (str): The password to be checked.

    Returns:
    int: An integer indicating the strength of the password:
        - 0: No match found in the dictionary.
        - 1: Direct match found in the dictionary.
        - 2: Substring match found in the dictionary.
        - 3: Substring match found in the dictionary after character demunging.
    """
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


def spray_attack(password):
    """
    Perform a spray attack to estimate the likelihood of a user's password being chosen
    among randomly selected passwords.

    Args:
    password (str): The user's password to be analyzed.

    Returns:
    str: A formatted probability representing the likelihood of the user's password being chosen among 5
    random passwords.
    """
    # Count occurrences of the user's password in the entire dictionary
    user_password_frequency = DICTIONARY.count(password)

    # Calculate the total number of passwords in the dictionary (including duplicates)
    total_passwords = len(DICTIONARY)

    # Calculate the percentage of the user's password in the total number of passwords
    user_password_percentage = (user_password_frequency / total_passwords) * 100

    # Calculate the probability of the user's password being chosen among 5 random passwords
    probability_spray = (user_password_percentage / 100) * (5 / total_passwords)

    # Format the probability for presentation
    prob = "{:.2e}".format(probability_spray) if probability_spray < 0.01 else "{:.2f}".format(probability_spray)
    return prob


def analyze_password(password):
    """
    Analyze the strength of a password based on various criteria and print the analysis.

    Args:
    password (str): The password to be analyzed.
    """
    alphanumeracy, length, entropy = check_alphanumeracy(password), check_length(password), calculate_entropy(password)
    bft_results = estimate_bft(entropy)
    dictionary_attack_result = dictionary_attack(password)
    spray_attack_result = 0.00
    if dictionary_attack_result == 1:
        spray_attack_result = spray_attack(password)

    print(
        f"\nPassword {'Contains only letters and numbers' if alphanumeracy else 'Contains more than just letters and numbers'}",
        f"\nPassword Length: {length}",
        f"\nEntropy: {entropy:.2f} bits",
        "\nBrute Force Time:",
        f"\nLower End Estimate: {bft_results[0]}",
        f"\nHigher End Estimate: {bft_results[1]}",
        )
    print("Dictionary Attack Estimate: ", end='')
    if dictionary_attack_result == 1:
        print("Vulnerable")
    elif dictionary_attack_result == 2:
        print("Somewhat Vulnerable")
    elif dictionary_attack_result == 3:
        print("Distantly Vulnerable")
    else:
        print("Not Vulnerable")
    print(f"Spray Attack Vulnerability Estimate: {'NA' if spray_attack_result == '0.00' else spray_attack_result + ' %'}")


def main():
    """
    The main function to interactively check the strength of passwords entered by the user.
    """
    while True:
        password = get_password()

        analyze_password(password)
        choice = input("\nCheck another password? (y/n): ")
        if choice.lower() != "y":
            break


if __name__ == "__main__":
    main()
