 _______ _________ _        _______    _______           _______  _______  _       
(  ____ \\__   __/( \      (  ____ \  (  ____ \|\     /|(  ____ \(  ____ \| \    /\
| (    \/   ) (   | (      | (    \/  | (    \/| )   ( || (    \/| (    \/|  \  / /
| (__       | |   | |      | (__      | |      | (___) || (__    | |      |  (_/ / 
|  __)      | |   | |      |  __)     | |      |  ___  ||  __)   | |      |   _ (  
| (         | |   | |      | (        | |      | (   ) || (      | |      |  ( \ \ 
| )      ___) (___| (____/\| (____/\  | (____/\| )   ( || (____/\| (____/\|  /  \ \
|/       \_______/(_______/(_______/  (_______/|/     \|(_______/(_______/|_/    \/ 

A Python-based file analysis utility that allows you to analyze file types, extract hexdumps, retrieve ASCII strings, and search for IPs, emails, and URLs in a file.
Features

## Features
- File Type Analysis: Uses the file command to determine the MIME type of a file.
- Hexdump Generation: Generates and saves the file's hexdump.
- ASCII Strings Extraction: Extracts printable strings from binary files.
- Search for Patterns:
    - IPv4 Addresses
    - Email Addresses
    - URLs
- File Hash Calculation: Computes file hashes using algorithms like SHA256, MD5, or SHA1.

## Dependencies
Ensure the following tools and libraries are installed:
System Tools:
    - file
    - xxd or hexdump
    - strings

Python Libraries:
The script uses standard Python libraries. However, ensure you are running:
    - Python 3.6+

## Installation
Clone the repository:

```
git clone https://github.com/yourusername/file-analysis-tool.git
cd file-analysis-tool
```
Make the script executable (optional):
```
chmod +x file_check.py
```
## Usage
Run the script:
```
python3 file_check.py
```
## Step-by-step:
Enter the file path to analyze when prompted.
Specify the hash type for checksum calculation (sha256, md5, etc.).
Choose one of the following menu options:
	1: View file type
	2: Save file hexdump to a new file
    3: Save strings to a new file
	4: View file type, save hexdump, and strings
    5: Search for IP addresses in the file
    6: Use all methods (comprehensive analysis)

Example:

Enter the file path to analyze: /path/to/your/file  
Enter the hash type to use (e.g., 'md5', 'sha256', 'sha1'): sha256  
Choose an option (1/2/3/4/5/6): 6

## Example Output

Analyzing file type...
The file '/path/to/your/file' is of type: application/octet-stream

Saving hexdump...
Hexdump generated and saved to: file_hexdump.txt

Saving strings...
Strings extracted and saved to: file_strings.txt

Searching for IP addresses in the extracted strings file...
All IP addresses found:
['192.168.1.1', '10.0.0.2']

Searching for email addresses...
Email addresses found in 'file_strings.txt':
user@example.com

Searching for URLs...
URLs found in 'file_strings.txt':
https://example.com

Calculating SHA256 hash...
SHA256 hash of '/path/to/your/file': abcdef1234567890...

## Code Highlights
   - Modular Design: Functions are independent and reusable.
   - Error Handling: Graceful failure messages when tools or files are missing.
   - Portability: Works on Linux and macOS environments.