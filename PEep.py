# TODO: Refactor functions
# TODO: Raw and virtual size
# TODO: A "Suspicious?" indicator (will use several parameters)
# TODO: Section starting addresses
# TODO: Entry point address
# TODO: Compilation time
# TODO: Section data dump to command-line or file
import os
import sys
import math
import pefile
import datetime
from argparse import *

is_verbose = False


def arguments():
    """
    Establishes argument-handling using the argparse module.
    :return: An Arguments object
    """
    description = "PEep is a tool for performing basic static analysis on the portable executable format of a Windows" \
                  " executable file. Its main function is to calculate the entropy of each PE section of a file " \
                  "to help determine if the file is packed with malicious intent."
    # Options with flags
    options = {
        "verbose": ["-v", '--verbose'],
        "section": ["-s", "--section"],
        "file": ["-f", "--file"],
        "threat": ["-t", "--threat"],
        "dump": ["-d", "--dump"],
        "imports": ["-i", "--imports"]
    }

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
    parser.add_argument(
        options.get("threat")[0],
        options.get("threat")[1],
        action="store_true"
    )
    parser.add_argument(
        options.get("imports")[0],
        options.get("imports")[1],
        action="store_true"
    )
    parser.add_argument(
        options.get("dump")[0],
        options.get("dump")[1],
        nargs=2,
        metavar="[File Name]",
        help="Requires the [-s, --section] option. Hex dump the section to a specified file in the "
             "working directory"
    )
    # Return the parsed arguments as a dictionary
    return vars(parser.parse_args())


def get_entropy(section):
    """
    Calculates the entropy of the given PE section
    :param section: PE section
    :return: The entropy as a floating-point number
    """
    section_name = section.Name.decode("utf-8")
    if is_verbose:
        print("* Calculating for %s..." % section_name)
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

        freq_list.append(float(counter) / length)

    entropy = 0.0
    if is_verbose:
        print("* Calculating Shannon entropy for %s..." % section_name)
    for frequency in freq_list:
        if frequency > 0:
            entropy = entropy + frequency * math.log(frequency, 2)

    entropy = -entropy
    return entropy


def collect(filename):
    """
    Collects the data from the PE format of the specified filename. It assumes that the file already exists in the
    working directory.
    :param filename: String representing the file's name
    :return: Dictionary containing all collected data
    """
    data = {}
    file = pefile.PE(filename, fast_load=False)

    if file.DOS_HEADER.dump_dict().get('e_magic').get('Value') != 23117:
        with open(filename, mode='rb') as file:
            file_data = file.read()
            signature = file_data[:2].decode("utf-8")
            if signature != 'MZ':
                pass
            else:
                raise pefile.PEFormatError("File: %s doesn't contain 'MZ' magic value" % filename)

    data.update({'Section Count': file.FILE_HEADER.NumberOfSections})
    data.update({'Page Count': file.DOS_HEADER.dump_dict().get('e_cp').get('Value')})
    data.update({'Time': str(datetime.datetime.fromtimestamp(file.FILE_HEADER.TimeDateStamp))})

    # TODO: Add more machines (MIPS, RISC-V, Hitachi)
    # Sets the machine by comparing returned integer from FILE_HEADER to a predetermined dictionary of machines
    machine = file.FILE_HEADER.dump_dict().get('Machine').get('Value')
    machines_dict = {34404: "x86-64", 332: "Intel i386", 448: "ARM", 43620: "ARM64", 3772: "EFI"}
    if machines_dict.get(machine):
        data.update({'Machine': machines_dict.get(machine)})
    else:
        data.update({'Machine': "Unknown"})

    data.update({'Entry Point': file.OPTIONAL_HEADER.dump_dict().get('AddressOfEntryPoint').get('Value')})

    # Sets the subsystem by comparing returned integer from OPTIONAL_HEADER to a predetermined dictionary of subsystems
    subsystem = file.OPTIONAL_HEADER.dump_dict().get('Subsystem').get('Value')
    subsystems_dict = {1: "Native", 2: "Windows GUI", 3: "Windows CUI", 5: "OS/2 CUI", 7: "POSIX CUI",
                       8: "Native Windows", 9: "Windows CE", 10: "EFI Application", 16: "Windows Boot Application"}
    if subsystems_dict.get(subsystem):
        data.update({'Subsystem': subsystems_dict.get(subsystem)})
    else:
        data.update({'Subsystem': "Unknown"})

    # Gets information on each section including name, entropy, address, virtual size, and raw size
    sections_dict = {}
    for section in file.sections:
        section_name = section.Name.decode("utf-8").rstrip('\x00')
        sections_dict.update({
            section_name: {
                'name': section_name,
                'entropy': round(get_entropy(section), 5),
                'address': hex(section.VirtualAddress),
                'Virtual Size': hex(section.Misc_VirtualSize),
                'Raw Size': hex(section.SizeOfRawData)
            }
        })
    # Updates the data dictionary with a sections dictionary
    data.update({'Sections': sections_dict})

    return data


# Main function
def main():
    global is_verbose
    ascii_art = " ____  _____       \n|  _ \\| ____|___ _ __  \n| |_) |  _| / _ \\ '_ \\ \n|  __/| |__|  __/ |_) |\n" \
                "|_|   |_____\\___| .__/ \n                |_|    "

    print(ascii_art)

    # Grabs command-line arguments
    args = arguments()
    # print(args)                         # TESTING
    filename = args.get('file')[0]
    section = args.get('section')
    is_verbose = args.get('verbose')

    # TODO: Call functions here based on args
    if os.path.exists(filename) and os.path.isfile(filename):
        if section:
            pass
        if args.get('threat'):
            pass
        if args.get('dump'):
            pass
        if args.get('imports'):
            pass

        data = collect(filename)
        print("============================[File]============================")
        print('File Name : "%s"' % filename)
        for value in data:
            if value != "Sections":
                print("%s : %s" % (value, data.get(value)))
            else:
                print("==========================[Sections]==========================")
                for section in data.get(value):
                    print('%s:' % section)
                    print('    Address : %s' % data.get(value).get(section).get('address'))
                    print('    Entropy : %s' % data.get(value).get(section).get('entropy'))
                    print('    Raw Size : %s' % data.get(value).get(section).get('Raw Size'))
                    print('    Virtual Size : %s' % data.get(value).get(section).get('Virtual Size'))


if __name__ == "__main__":
    main()

