import argparse

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
    parser.add_argument('-o', '--output', dest='output_file', type=str, required=True, help='A file to save all results to.')
    parser.add_argument('-r', '--report', dest='report_file', type=str, required=True, help='A file to save report style results to.')
    parser.add_argument('-l', '--lm-list', dest='lm_list_file', type=str, help='File to save list of accounts with LM hashes (one per line).')
    parser.add_argument('-s', '--same-pass-list', dest='same_pass_file', type=str, help='File to save accounts with same passwords (comma-separated per line).')
    parser.add_argument('-b', '--blank-list', dest='blank_list_file', type=str, help='File to save list of accounts with blank passwords (one per line).')

    args = parser.parse_args()

    if args.output_file:
        global output_file
        output_file = args.output_file

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

    # Print summary to terminal
    print(f"\n[+] Accounts with LM Hashes: {len(lm_accounts)}")
    
    # Calculate total accounts with reused passwords
    total_reuse_accounts = sum(len(group) for group in accounts_same_pass)
    print(f"[+] {len(accounts_same_pass)} passwords used across {total_reuse_accounts} accounts")
    
    print(f"[+] Accounts with Blank Passwords: {len(blank_accounts)}")
    
    print(f"\n[+] Output Files:")
    print(f"    Main output: {args.output_file}")
    print(f"    Report: {args.report_file}")
    if args.lm_list_file:
        print(f"    LM accounts list: {args.lm_list_file}")
    if args.same_pass_file:
        print(f"    Same password list: {args.same_pass_file}")
    if args.blank_list_file:
        print(f"    Blank password list: {args.blank_list_file}")
    print()

    # Write main report file
    with open(args.report_file, "w") as report_file:
        report_text = f"[+] Accounts with LM Hashes: {', '.join(sorted(lm_accounts))}\n"
        report_text += f"[+] Accounts with Blank Passwords: {', '.join(sorted(blank_accounts))}\n"
        report_text += "[+] Accounts with the Same Passwords:\n"
        for accounts in sorted(accounts_same_pass):
           report_text += f"\nSame Password: {', '.join(accounts)}"

        report_file.writelines(report_text)

    # Write LM accounts list file (one per line)
    if args.lm_list_file:
        with open(args.lm_list_file, "w") as lm_file:
            for account in sorted(lm_accounts):
                lm_file.write(f"{account}\n")

    # Write same password accounts file (comma-separated per line)
    if args.same_pass_file:
        with open(args.same_pass_file, "w") as same_file:
            for accounts in sorted(accounts_same_pass):
                same_file.write(f"{', '.join(accounts)}\n")

    # Write blank password accounts list file (one per line)
    if args.blank_list_file:
        with open(args.blank_list_file, "w") as blank_file:
            for account in sorted(blank_accounts):
                blank_file.write(f"{account}\n")

    return

if __name__ == "__main__":
    main()