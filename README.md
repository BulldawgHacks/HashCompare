# HashCompare

A Python tool for analyzing hash dumps produced by secretsdump.py to identify security weaknesses in Windows credential usage.

## Features

- **Blank Password Detection**: Identifies accounts with blank/empty passwords
- **LM Hash Detection**: Finds accounts still using the weak LM hashing algorithm
- **Password Reuse Analysis**: Detects accounts sharing the same passwords by comparing NTLM hashes
- **Multiple Output Formats**: Generates detailed logs, sanitized reports, and structured account lists

## Requirements

- Python 3.x
- Hash dump output from secretsdump.py (Impacket)

## Installation

```text
git clone https://github.com/BulldawgHacks/HashCompare.git
cd HashCompare
```

## Usage

### Basic Usage

```text
python HashCompare.py -o output.txt -r report.txt -l lm_hashes.txt -s same_passwords.txt -b blank_passwords.txt dump.txt
```

### Command-Line Options

```text
usage: HashCompare.py [-h] -o OUTPUT_FILE -r REPORT_FILE [-l LM_LIST_FILE]
                      [-s SAME_PASS_FILE] [-b BLANK_LIST_FILE]
                      dump_file

A script to analyze a secrets dump, compare NTLM hashes for re-use, identify accounts with blank passwords, and
identify usage of LM hashing.

positional arguments:
  dump_file             The raw secrets dump output.

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        A file to save all results to.
  -r REPORT_FILE, --report REPORT_FILE
                        A file to save report style results to.
  -l LM_LIST_FILE, --lm-list LM_LIST_FILE
                        File to save list of accounts with LM hashes (one per
                        line).
  -s SAME_PASS_FILE, --same-pass-list SAME_PASS_FILE
                        File to save accounts with same passwords (comma-
                        separated per line).
  -b BLANK_LIST_FILE, --blank-list BLANK_LIST_FILE
                        File to save list of accounts with blank passwords
                        (one per line).
```

## Output Files

### Main Output File (`-o`)

Contains detailed findings with hash values and full account information. Includes:

- All accounts using LM hashes with their full hash lines
- Groups of accounts sharing passwords with NTLM hash values
- All accounts with blank passwords

### Report File (`-r`)

Sanitized summary suitable for reports - no credential information included. Contains:

- Summary of accounts with LM hashes
- Summary of accounts with blank passwords
- Grouped listings of accounts sharing passwords

### LM Accounts List (`-l`)

Simple list format, one account per line:

```text
user1
user2
user3
```

### Same Password Accounts List (`-s`)

Comma-separated groups, one group per line:

```text
user1, user2, user3
user4, user5
admin, backup_admin
```

### Blank Password Accounts List (`-b`)

Simple list format, one account per line:

```text
guest
test_user
temp_account
```

## Example Output

### Terminal Output

```text
[+] Accounts with LM Hashes: 5
[+] 3 passwords used across 12 accounts
[+] Accounts with Blank Passwords: 2

[+] Output Files:
    Main output: output.txt
    Report: report.txt
    LM accounts list: lm_accounts.txt
    Same password list: same_passwords.txt
    Blank password list: blank_passwords.txt
```

### Example Report File Content

```text
[+] Accounts with LM Hashes: admin, legacy_service, old_backup
[+] Accounts with Blank Passwords: guest, test_user
[+] Accounts with the Same Passwords:

Same Password: admin, backup_admin, secondary_admin
Same Password: sqlservice, webservice
Same Password: user1, user2, user3, user4
```

## Input Format

HashCompare expects secretsdump.py output in the standard format:

```text
DOMAIN\username:RID:LM_hash:NTLM_hash:::
```

Example:

```text
CORP\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CORP\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CORP\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
```

## References

- [Impacket](https://github.com/fortra/impacket) project for secretsdump.py
