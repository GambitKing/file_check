######################################################################################
# License: GNU General Public License v.3.0                                          #
# Day of creation: December 12th, 2024                                               #
# Author: GambitKing                                                                 #
#                                                                                    #
# file_check.py, python tool for file analysis                                       #
######################################################################################

import os
import subprocess
import re
import hashlib

from ascii_title import logo
print(logo)

email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"

def calculate_file_hash(file_path, hash_type='sha256'):
    # Calculate and return the hash of a file using the specified algorithm. 
    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file.")
        return

    try:
        # Create the appropriate hash object
        hash_func = getattr(hashlib, hash_type)()
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):  # Read the file in chunks
                hash_func.update(chunk)
        print(f"{hash_type.upper()} hash of '{file_path}': {hash_func.hexdigest()}")
        return hash_func.hexdigest()
    except AttributeError:
        print(f"Error: Unsupported hash type '{hash_type}'. Please use a valid hash type (e.g., 'md5', 'sha256').")
    except Exception as e:
        print(f"Error calculating hash for '{file_path}': {e}")

def run_command(command):
    #Executes a shell command and captures the output.
    try:
        result = subprocess.run(
            command if isinstance(command, list) else command,
            shell=isinstance(command, str),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}\n{e.stderr}")
        return None

def analyze_file(file_path):
    # Analyze the file type using the 'file' command.
    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file.")
        return None
    # Use the 'file' command to analyze the file type with --mime-type and -b flags
    command = ["file", "--mime-type", "-b", file_path]
    file_type = run_command(command)

    if file_type:
        mime_type = file_type.strip()
        print(f"The file '{file_path}' is of type: {mime_type}")
        return mime_type
    else:
        print(f"Failed to analyze the file '{file_path}'.")
        return None

def save_hexdump(file_path):
    # Save the hexdump of the file to a new file.
    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file.")
        return None
    base_name = os.path.basename(file_path)
    new_hexdump_file = f"{base_name}_hexdump.txt"

    if run_command("command -v xxd"):
        command = f"xxd {file_path} > {new_hexdump_file}"
        tool_used = "xxd"
    else:
        command = f"hexdump -C {file_path} > {new_hexdump_file}"
        tool_used = "hexdump"

    run_command(command)
    print(f"Hexdump generated using '{tool_used}' and saved to: {new_hexdump_file}")
    return new_hexdump_file

def save_strings(file_path):
    # Save the extracted strings of the file to a new file.
    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file.")
        return
    base_name = os.path.basename(file_path)
    new_strings_file = f"{base_name}_strings.txt"

    command = f"strings {file_path} > {new_strings_file}"
    run_command(command)
    print(f"Strings extracted and saved to: {new_strings_file}")
    return new_strings_file

def find_ip_in_string(string):
    # Regular expression for IPv4 addresses, ensuring each octet is 0–255
    pattern = r"\b((?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\." \
              r"(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\." \
              r"(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\." \
              r"(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\b"
    
    # Find all the IP
    match = re.findall(pattern, string)
    return match

def search_ip_in_file(file_path):
    # Search for an IP address within a file's content.
    if not file_path or not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file.")
        return

    try:
        with open(file_path, 'r') as file:
            content = file.read()
            ip_list = find_ip_in_string(content)
            filtered_ip_list = [ip for ip in ip_list if sum(1 for octet in ip.split('.') if octet == '0') < 2]

            if filtered_ip_list:
                print("\nAll IP addresses found:")
                print(filtered_ip_list)
            else:
                print("No IP addresses found.")
    except Exception as e:
        print(f"Error reading the file '{file_path}': (e)")

def search_pattern_in_file(file_path, pattern, description="pattern"):
    # Search for a specific pattern within a file's content and print matches.
    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file.")
        return

    try:
        with open(file_path, 'r') as file:
            content = file.read()
            matches = re.findall(pattern, content)
            
            if matches:
                print(f"\n{description.capitalize()} found in '{file_path}':")
                for match in matches:
                    print(match)
            else:
                print(f"No {description} found in '{file_path}'.")
    except Exception as e:
        print(f"Error reading the file '{file_path}': {e}")

def use_all_methods(file_path, hash_type):
    # Use all methods: analyze file, generate hexdump, extract strings, and search for IPs in strings.
    print("Analyzing file type...")
    analyze_file(file_path)
    print("Saving hexdump...")
    save_hexdump(file_path)
    print("Saving strings...")

    strings_file = save_strings(file_path)
    if not strings_file or not os.path.isfile(strings_file):
        print("Error: Failed to generate the strings file. Skipping further analysis.")
        return
    else:
        print(f"Strings saved to: {strings_file}")

    # Now search for IP addresses in the extracted strings file
    print("\nSearching for IP addresses in the extracted strings file...")
    search_ip_in_file(strings_file)
    # Search for Emails
    search_pattern_in_file(strings_file, email_pattern, description="email address")
    # Search for URLs
    search_pattern_in_file(strings_file, url_pattern, description="URL")
    # Calculate the hash
    calculate_file_hash(file_path, hash_type)

def menu():
    # Display a menu for the user to choose an option.
    print("\nChoose an option:")
    print("1. View file type")
    print("2. Save hexdump to a new file")
    print("3. Save strings to a new file")
    print("4. View file type, save hexdump, and strings")
    print("5. Search for IP addresses in the file")
    print("6. Use all methods (Analyze file, save hexdump, save strings, check strings for IP, check URL's)")

if __name__ == "__main__":
    file_path = input("Enter the file path to analyze: ").strip()
    hash_type = input("Enter the hash type to use (e.g., 'md5', 'sha256', 'sha1'): ").strip().lower()

    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file path.")
        exit(1)

    menu()
    choice = input("Enter your choice (1/2/3/4/5/6): ").strip()

    if choice == '1':
        analyze_file(file_path)
    elif choice == '2':
        save_hexdump(file_path)
    elif choice == '3':
        save_strings(file_path)
    elif choice == '4':
        analyze_file(file_path)
        save_hexdump(file_path)
        save_strings(file_path)
    elif choice == '5':
        search_ip_in_file(file_path)
    elif choice == '6':
        use_all_methods(file_path, hash_type)
    else:
        print("Invalid choice. Please choose a valid option.")