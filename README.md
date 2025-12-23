# HashCompare

A Python tool for analyzing hash dumps produced by secretsdump.py to identify security weaknesses in Windows credential usage.

## Features

- **Blank Password Detection**: Identifies accounts with blank/empty passwords
- **LM Hash Detection**: Finds accounts still using the weak LM hashing algorithm
- **Password Reuse Analysis**: Detects accounts sharing the same passwords by comparing NTLM hashes
- **Organized Output**: Automatically creates timestamped directories with multiple analysis files

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
python HashCompare.py dump.txt
```

This will create a timestamped directory (e.g., `password_analysis_20241223_143052`) containing all output files.

### Specify Output Directory

```text
python HashCompare.py dump.txt -d my_analysis
```

### Command-Line Options

```text
usage: HashCompare.py [-h] [-d OUTPUT_DIR] dump_file

A script to analyze a secrets dump, compare NTLM hashes for re-use, and
identify usage of LM hashing.

positional arguments:
  dump_file             The raw secrets dump output.

options:
  -h, --help            show this help message and exit
  -d OUTPUT_DIR, --directory OUTPUT_DIR
                        Directory to save output files to. If not specified,
                        creates a timestamped directory.
```

## Output Files

All output files are automatically created in the specified or timestamped directory:

### Comparison Output.txt

Contains detailed findings with hash values and full account information. Includes:

- All accounts using LM hashes with their full hash lines
- Groups of accounts sharing passwords with NTLM hash values
- All accounts with blank passwords

### LM Hash Usage.txt

Simple list format, one account per line:

```text
user1
user2
user3
```

### Password Reuse Account List.txt

Flattened list of all accounts that share passwords with at least one other account, one per line:

```text
admin
backup_admin
secondary_admin
sqlservice
webservice
```

### Accounts with the Same Password.txt

Comma-separated groups showing which accounts share passwords, one group per line:

```text
admin, backup_admin, secondary_admin
sqlservice, webservice
user1, user2, user3, user4
```

### Accounts with Blank Passwords.txt

Simple list format, one account per line:

```text
guest
test_user
temp_account
```

## Example Output

### Terminal Output

```text
[+] Output Directory: password_analysis_20241223_143052
[+] Output Files:
    Comparison Output: Comparison Output.txt
    LM Hash Usage: LM Hash Usage.txt
    Password Reuse Account List: Password Reuse Account List.txt
    Accounts with Same Password: Accounts with the Same Password.txt
    Accounts with Blank Passwords: Accounts with Blank Passwords.txt

[+] Accounts with LM Hashes: 5
[+] Accounts with Reused Passwords: 12
[+] 3 unique passwords reused across 12 accounts
[+] Accounts with Blank Passwords: 2
```

### Example Comparison Output.txt Content

```text
[LM Hash In Use] CORP\admin:500:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::
[Same Hash: 8846f7eaee8fb117ad06bdd830b7586c] admin, backup_admin, secondary_admin
[Same Hash: a4f49c406510bdcab6824ee7c30fd852] sqlservice, webservice
[Blank Password] guest
[Blank Password] test_user
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

## Understanding the Statistics

- **Accounts with LM Hashes**: Number of accounts using the weak LM hashing algorithm (security risk)
- **Accounts with Reused Passwords**: Total number of accounts that share passwords with other accounts
- **Unique passwords reused**: Number of distinct passwords that are used by multiple accounts
- **Accounts with Blank Passwords**: Number of accounts with no password set (critical security risk)
