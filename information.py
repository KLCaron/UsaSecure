def launch_information():
    """
    Launch an information session to provide explanations about terminology used in the program.
    """
    explanations = {
        "alphanumeracy": "\nAlphanumeracy refers to whether the password contains "
                         "\nonly alphanumeric characters (letters and numbers), or not.",
        "length": "\nLength refers to the number of characters in the password.",
        "entropy": "\nEntropy is a measure of password strength based on the number of unique characters it contains. "
                   "\nHere we present it in 'bits', the smallest unit of data, capable of representing two distinct "
                   "\nstates, usually a 0 or 1. Our measure shows the number of bits required to represent the "
                   "\nuncertainty or randomness of the password. Higher entropy indicates a stronger password",
        "brute force attack": "\nA brute force attack is a trial-and-error method used to obtain information such as a "
                              "\nuser password or personal identification number (PIN). Here we present estimates on"
                              "\nthe amount of time such an attack could be expected to take to crack the given "
                              "\npassword. Our upper estimate is based on the computational power of a relatively "
                              "\nstrong computer, which we assume, based on available data, to be capable of "
                              "\napproximately 100 billion password attempts per second. The lower estimate we provide "
                              "\nis based on the computational power of a relatively average computer, that any random "
                              "\nperson might be expected to possess; capable of approximately 2.5 billion password "
                              "\nattempts per second. It is important to note that these values are still an estimate, "
                              "\nand could be wrong.",
        "dictionary attack": "\nA dictionary attack is a method of breaking into a password-protected computer or server "
                             "\nby systematically entering every word in a given dictionary as a password. For our "
                             "\npurposes, the 'dictionary' of passwords we are using was acquired from a 2021 fortinet "
                             "\ndata breach, and so contains some 79,000 passwords used by real people, and available"
                             "\n freely on the internet. The metrics we display here come as 'Vulnerable', 'Somewhat "
                             "\nVulnerable', 'Distantly Vulnerable', and 'Not Vulnerable', in that order of severity."
                             "\n Vulnerable means your password was found in this leak, distantly vulnerable means some"
                             "\nsubset of your password was found in this leak (eg, your password is 'hellomom', and "
                             "\nthe leak contains 'mom'), distantly vulnerable means some substitution, or 'munged' "
                             "\nvariation of your password was found (eg, your password is 'h3ll0m0m', and the leak "
                             "\ncontains 'hellomom'), and finally not vulnerable means no variation of your password"
                             "\n was found. It is important to note that this value is an estimate, and could be "
                             "\nwrong.",
        "spray attack": "\nA spray attack is a type of brute force attack where an attacker tries a small number of "
                        "\npasswords against multiple accounts. In our case, we assume the attacker is getting 5 tries"
                        "\n to enter your password correctly before being locked out. We also assume that the attacker "
                        "\nis pulling the passwords they will attempt at random from a database of recently leaked "
                        "\npasswords (ie, from the database we're using to check our dictionary attack). This is why "
                        "\nthis number is only shown for passwords marked as 'Vulnerable' by the dictionary attack "
                        "\ncheck. The percentage given is the change that your password would be one of 5 randomly "
                        "\nselected passwords used in such an attack. It is important to note that this value is an "
                        "\nestimate, and could be wrong."
    }
    print("What would you like to learn more about?")
    print("Available terms to ask about:", ", ".join(explanations))
    while True:
        choice = input("\nEnter a term, or its first letter, to receive more information, or 'q' to quit: ").lower()
        if choice == 'q':
            return
        elif choice in explanations:
            print(explanations[choice])
        else:
            matched_terms = [key for key in explanations if key.startswith(choice)]
            if matched_terms:
                print(explanations[matched_terms[0]])
            else:
                print("Sorry, the term you entered is not recognized.")
