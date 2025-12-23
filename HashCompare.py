import argparse
import os
from datetime import datetime

output_file = ""
same_hash_list = []

def identify_lm(hash_line_list):
    lm_accounts = set()

    for hash_line in hash_line_list:
        result = ""

        if "aad3b435b51404eeaad3b435b51404ee" not in hash_line:
            result = f"[LM Hash In Use] {hash_line}"

            parts = hash_line.split(":", 4)
            account = parts[0].strip()
            lm_accounts.add(account)

            if output_file != "":
                with open(output_file, "a") as file:
                    file.write(result + "\n")

    return lm_accounts

def compare_ntlm(hash_line_list):
    global same_hash_list

    # store canonical tuples (sorted) to avoid ordering duplicates
    accounts_same_pass = set()

    for hash_line in hash_line_list:
        if "aad3b435b51404eeaad3b435b51404ee" in hash_line:

            parts = hash_line.split(":", 4)
            # defensive checks in case the line is malformed
            if len(parts) < 4:
                continue

            ntlm_hash = parts[3].strip()
            account = parts[0].strip()

            # skip the well-known blank hash early
            if ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue

            same_password = [account]

            for other_line in hash_line_list:
                other_parts = other_line.split(":", 4)
                if len(other_parts) < 4:
                    continue
                other_ntlm = other_parts[3].strip()
                other_account = other_parts[0].strip()

                if ntlm_hash == other_ntlm and account != other_account:
                    same_password.append(other_account)

            if len(same_password) > 1:
                # canonicalize the account group to a sorted tuple
                canonical_accounts = tuple(sorted({a.strip() for a in same_password}))
                # only add/print once per NTLM hash
                if ntlm_hash not in same_hash_list:
                    same_hash_list.append(ntlm_hash)

                    accounts_display = ", ".join(canonical_accounts)
                    result = f"[Same Hash: {ntlm_hash}] {accounts_display}"

                    if output_file != "":
                        with open(output_file, "a") as file:
                            file.write(result + "\n")

                # keep the canonical tuple in the returned set to avoid order variants
                accounts_same_pass.add(canonical_accounts)

    return accounts_same_pass

def blank_passwords(hash_line_list):
    blank_accounts = set()

    for hash_line in hash_line_list:
        parts = hash_line.split(":", 4)
        if len(parts) < 4:
            continue

        ntlm_hash = parts[3].strip()
        account = parts[0].strip()

        if ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
            if account not in blank_accounts:
                blank_accounts.add(account)

    
    for blank_account in sorted(blank_accounts):
        message = f"[Blank Password] {blank_account}"
        if output_file != "":
            with open(output_file, "a") as file:
                file.write(message + "\n")

    return blank_accounts

def main():
    parser = argparse.ArgumentParser(description="A script to analyze a secrets dump, compare NTLM hashes for re-use, and identify usage of LM hashing.")

    parser.add_argument('dump_file', type=str, help='The raw secrets dump output.')
    parser.add_argument('-d', '--directory', dest='output_dir', type=str, help='Directory to save output files to. If not specified, creates a timestamped directory.')

    args = parser.parse_args()

    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        # Create timestamped directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"password_analysis_{timestamp}"
    
    # Create directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Define output file paths
    comparison_output = os.path.join(output_dir, "Comparison Output.txt")
    lm_hash_file = os.path.join(output_dir, "LM Hash Usage.txt")
    reuse_account_list = os.path.join(output_dir, "Password Reuse Account List.txt")
    same_password_file = os.path.join(output_dir, "Accounts with the Same Password.txt")
    blank_password_file = os.path.join(output_dir, "Accounts with Blank Passwords.txt")

    # Set global output file
    global output_file
    output_file = comparison_output

    with open(args.dump_file, "r") as raw_dump_file:
        # preserve spaces inside usernames by reading line-by-line
        raw_dump_file_list = raw_dump_file.read().splitlines()

    hash_line_list = []

    for line in raw_dump_file_list:
        line = line.rstrip("\n")

        # split on whitespace to remove trailing stats
        first_field = line
        if " " in line:
            first_field = line.split()[0]

        if first_field.endswith(":::"):
            hash_line_list.append(first_field)

    lm_accounts = identify_lm(hash_line_list)

    accounts_same_pass = compare_ntlm(hash_line_list)

    blank_accounts = blank_passwords(hash_line_list)

    # Calculate accounts with reused passwords (flattened set)
    accounts_with_reused_passwords = set()
    for group in accounts_same_pass:
        accounts_with_reused_passwords.update(group)

    # Calculate statistics
    num_lm_accounts = len(lm_accounts)
    num_reused_accounts = len(accounts_with_reused_passwords)
    num_unique_reused_passwords = len(accounts_same_pass)
    num_blank_accounts = len(blank_accounts)

    print(f"\n[+] Output Directory: {output_dir}")
    print(f"[+] Output Files:")
    print(f"    Comparison Output: Comparison Output.txt")
    print(f"    LM Hash Usage: LM Hash Usage.txt")
    print(f"    Password Reuse Account List: Password Reuse Account List.txt")
    print(f"    Accounts with Same Password: Accounts with the Same Password.txt")
    print(f"    Accounts with Blank Passwords: Accounts with Blank Passwords.txt")
    print()
    print(f"[+] Accounts with LM Hashes: {num_lm_accounts}")
    print(f"[+] Accounts with Reused Passwords: {num_reused_accounts}")
    print(f"[+] {num_unique_reused_passwords} unique passwords reused across {num_reused_accounts} accounts")
    print(f"[+] Accounts with Blank Passwords: {num_blank_accounts}")

    # Write LM Hash Usage file
    with open(lm_hash_file, "w") as lm_file:
        for account in sorted(lm_accounts):
            lm_file.write(f"{account}\n")

    # Write Password Reuse Account List file
    with open(reuse_account_list, "w") as reuse_file:
        for account in sorted(accounts_with_reused_passwords):
            reuse_file.write(f"{account}\n")

    # Write Accounts with the Same Password file
    with open(same_password_file, "w") as same_file:
        for accounts in sorted(accounts_same_pass):
            same_file.write(f"{', '.join(accounts)}\n")

    # Write Accounts with Blank Passwords file
    with open(blank_password_file, "w") as blank_file:
        for account in sorted(blank_accounts):
            blank_file.write(f"{account}\n")

    return

if __name__ == "__main__":
    main()