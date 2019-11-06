# TODO: Replace argument parsing code with argparse module
# TODO: Refactor functions
# TODO: Raw and virtual size
# TODO: A "Suspicious?" indicator (will use several parameters)
# TODO: Section starting addresses
# TODO: Entry point address
# TODO: Compilation time

import sys
import math
import pefile
import argparse

verbose = False


def print_help():
    """
    Prints the main description and help message for the program
    :return:
    """
    ascii_art = " ____  _____       \n|  _ \\| ____|___ _ __  \n| |_) |  _| / _ \\ '_ \\ \n|  __/| |__|  __/ |_) |\n" \
                "|_|   |_____\\___| .__/ \n                |_|    "
    print("********************************|PE Entropy Calculator|********************************")
    print(ascii_art)
    print("Description:")
    print("\tPE Entropy Calculator will take in a portable executable (PE) file and calculate the")
    print("\tShannon entropy for each section (e.g, .text, .rsrc, .rdata). An entropy value will")
    print("\tbe between 0 and 8. The closer the entropy is to 8, the more likely the section is")
    print("\tencrypted or compressed.")
    print("Usage:")
    print("\tpython PE_Entropy_Calc.py [OPTIONS] [PE file name]")
    print("Options:")
    print("\t--file\t\tDisplay the entropy of the entire file")
    print("\t--verbose\tVerbose mode")
    print("***************************************************************************************")


def calculate(filename, check_file=False):
    """
    Calculates the entropies of the sections or entire file for the given PE file name. The file must
    be within the same working directory.
    :param filename: A string to the file within the working directory
    :param check_file: Whether or not to check the entropy of the entire file
    :return: List of 2-tuple with the values: (section name, entropy) for each section.
    """""
    section_entropies = []
    global verbose

    if verbose:
        print("* Loading %s*" % filename)
    with open(filename, mode='rb') as file:

        file_data = file.read()
        signature = file_data[:2].decode("utf-8")

        # TODO: Create a thorough check for PE format
        if signature != "MZ":
            print("* ERROR - File does not match the PE format - Missing 0x4D 0x5A (MZ) signature")
            sys.exit()

        # File entropy calculation
        if check_file:
            if verbose:
                print("* Checking file entropy (--file)...")
            size = len(file_data)
            freq_list = []

            if verbose:
                print("* Calculating byte frequencies...")
            for i in range(0, 256):
                counter = 0

                for byte in file_data:
                    if byte == i:
                        counter += 1

                freq_list.append(float(counter) / size)

            entropy = 0.0

            if verbose:
                print("* Calculating Shannon entropy for %s..." % filename)
            for frequency in freq_list:
                if frequency > 0:
                    entropy = entropy + frequency * math.log(frequency, 2)

            entropy = -entropy
            section_entropies.append((filename, entropy))
            if verbose:
                print("* File entropy calculating complete")

    # Section entropy calculations
    if verbose:
        print("* Checking section entropies...")
    file = pefile.PE(filename, fast_load=False)
    section_count = file.FILE_HEADER.NumberOfSections

    for section in file.sections:
        section_name = section.Name.decode("utf-8")
        if verbose:
            print("* Calculating for %s..." % section_name)
        section_address = hex(section.VirtualAddress)  # Will be used in future code
        data = section.get_data()
        length = len(data)
        freq_list = []

        if verbose:
            print("* Calculating byte frequencies...")
        for i in range(0, 256):
            counter = 0

            for byte in data:
                if byte == i:
                    counter += 1

            freq_list.append(float(counter)/length)

        entropy = 0.0
        if verbose:
            print("* Calculating Shannon entropy for %s..." % section_name)
        for frequency in freq_list:
            if frequency > 0:
                entropy = entropy + frequency * math.log(frequency, 2)

        entropy = -entropy
        section_entropies.append((section_name, entropy))
        if verbose:
            print("* %s entropy calculating complete" % section_name)

    return section_entropies


def print_entropies(section_entropies, check_file=False):
    """
    Prints out the entropies.
    :param section_entropies: A tuple consisting of entropies and their respective names
    :param check_file: Whether or not the user chose to check the entropy of the entire file
    :return:
    """
    if check_file:
        print('File entropy for "%s" : %f' % (section_entropies[0][0], section_entropies[0][1]))
    print("Section Entropies:")
    for entropy in section_entropies:
        if check_file and entropy == section_entropies[0]:
            pass
        else:
            print("%s: %f" % (entropy[0], entropy[1]))


# Main function
def main():
    global verbose
    if len(sys.argv) < 2:
        print_help()
    elif len(sys.argv) == 2:
        print("********************************|PE Entropy Calculator|********************************")
        print_entropies(calculate(filename=sys.argv[-1], check_file=False), check_file=False)
        print("***************************************************************************************")
    else:
        # TODO: check if the given argument is a folder
        check_file = False
        for argument in sys.argv:
            if argument == sys.argv[-1] or argument == sys.argv[0]:
                pass
            elif argument == "--verbose":
                verbose = True
            elif argument == "--file":
                check_file = True
            else:
                print_help()
        print("********************************|PE Entropy Calculator|********************************")
        print_entropies(calculate(filename=sys.argv[-1], check_file=check_file), check_file=check_file)
        print("***************************************************************************************")


if __name__ == "__main__":
    main()

