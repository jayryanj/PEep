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
from argparse import *

is_verbose = False


def arguments():
    """
    Establishes argument-handling using the argparse module.
    :return: An Arguments object
    """
    description = "PEep is a tool for performing static analysis on a portable executable (PE) file."
    options = {"verbose": ["-v", '--verbose'], "section": ["-s", "--section"], "file": ["-f", "--file"]}

    parser = ArgumentParser(description=description, usage="PEep.py [OPTIONS] [-f, --file] [File Name]")

    # Add arguments to the commandline
    parser.add_argument(
        options.get("file")[0],
        options.get("file")[1],
        required=True,
        nargs=1,
        metavar="[File Name]",
        help="Specified file name to analyze"
    )
    parser.add_argument(
        options.get("verbose")[0],
        options.get("verbose")[1],
        help="Verbosity mode - displays more information as the process is running",
        action="store_true"
    )
    parser.add_argument(
        options.get("section")[0],
        options.get("section")[1],
        nargs=1,
        metavar="[Section Name]",
        help="Specify a PE section to analyze (leave this option off to analyze ALL detected sections)"
    )
    # Return the parsed arguments
    return parser.parse_args()


def calculate(filename, check_file=False):
    """
    Calculates the entropies of the sections or entire file for the given PE file name. The file must
    be within the same working directory.
    :param filename: A string to the file within the working directory
    :param check_file: Whether or not to check the entropy of the entire file
    :return: List of 2-tuple with the values: (section name, entropy) for each section.
    """""
    section_entropies = []
    global is_verbose

    if is_verbose:
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
            if is_verbose:
                print("* Checking file entropy (--file)...")
            size = len(file_data)
            freq_list = []

            if is_verbose:
                print("* Calculating byte frequencies...")
            for i in range(0, 256):
                counter = 0

                for byte in file_data:
                    if byte == i:
                        counter += 1

                freq_list.append(float(counter) / size)

            entropy = 0.0

            if is_verbose:
                print("* Calculating Shannon entropy for %s..." % filename)
            for frequency in freq_list:
                if frequency > 0:
                    entropy = entropy + frequency * math.log(frequency, 2)

            entropy = -entropy
            section_entropies.append((filename, entropy))
            if is_verbose:
                print("* File entropy calculating complete")

    # Section entropy calculations
    if is_verbose:
        print("* Checking section entropies...")
    file = pefile.PE(filename, fast_load=False)
    section_count = file.FILE_HEADER.NumberOfSections

    for section in file.sections:
        section_name = section.Name.decode("utf-8")
        if is_verbose:
            print("* Calculating for %s..." % section_name)
        section_address = hex(section.VirtualAddress)  # Will be used in future code
        data = section.get_data()
        length = len(data)
        freq_list = []

        if is_verbose:
            print("* Calculating byte frequencies...")
        for i in range(0, 256):
            counter = 0

            for byte in data:
                if byte == i:
                    counter += 1

            freq_list.append(float(counter)/length)

        entropy = 0.0
        if is_verbose:
            print("* Calculating Shannon entropy for %s..." % section_name)
        for frequency in freq_list:
            if frequency > 0:
                entropy = entropy + frequency * math.log(frequency, 2)

        entropy = -entropy
        section_entropies.append((section_name, entropy))
        if is_verbose:
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
    ascii_art = " ____  _____       \n|  _ \\| ____|___ _ __  \n| |_) |  _| / _ \\ '_ \\ \n|  __/| |__|  __/ |_) |\n" \
                "|_|   |_____\\___| .__/ \n                |_|    "

    print(ascii_art)

    # Grabs command-line arguments 
    args = arguments()
    # TODO: Call functions here based on args


if __name__ == "__main__":
    main()

