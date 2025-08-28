import argparse

output_file = ""
same_hash_list = []

def identify_lm(hash_line_list):

    lm_accounts = set()

    for hash_line in hash_line_list:
        result = ""

        if "aad3b435b51404eeaad3b435b51404ee" not in hash_line:
            result = f"[LM Hash In Use] {hash_line}"

            account = hash_line.split(":")[0]
            lm_accounts.add(account)

            print(result)
            if output_file != "":
                with open(output_file, "a") as file:
                    file.write(result + "\n")

    return lm_accounts

def compare_ntlm(hash_line_list):

    global same_hash_list

    accounts_same_pass = set()

    for hash_line in hash_line_list:
        if "aad3b435b51404eeaad3b435b51404ee" in hash_line:

            result = ""

            ntlm_hash = hash_line.split(":")[3]
            account = hash_line.split(":")[0]

            same_password = []
            same_password.append(account)

            for hash_line in hash_line_list:
                if ntlm_hash == hash_line.split(":")[3] and account != hash_line.split(":")[0] and ntlm_hash != "31d6cfe0d16ae931b73c59d7e0c089c0":
                    same_password.append(hash_line.split(":")[0])
            
            if len(same_password) > 1:

                accounts = ", ".join(same_password)

                accounts_same_pass.add(accounts)
                
                result = f"[Same Hash: {ntlm_hash}] {accounts}"
                if ntlm_hash not in same_hash_list:
                    same_hash_list.append(ntlm_hash)
                    
                    print(result)
                    if output_file != "":
                        with open(output_file, "a") as file:
                            file.write(result + "\n")

    return accounts_same_pass

def blank_passwords(hash_line_list):

    blank_accounts = set()

    for hash_line in hash_line_list:
        result = ""

        ntlm_hash = hash_line.split(":")[3]
        account = hash_line.split(":")[0]

        if ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0" :
            result = f"[Blank Password] {account}"
            blank_accounts.add(account)

            print(result)
            if output_file != "":
                with open(output_file, "a") as file:
                    file.write(result + "\n")

    return blank_accounts

def main():
    parser = argparse.ArgumentParser(description="A script to analyze a secrets dump, compare NTLM hashes for re-use, and identify usage of LM hashing.")

    parser.add_argument('dump_file', type=str, help='The raw secrets dump output.')
    parser.add_argument('output_file', type=str, help='A file to save all results to.')
    parser.add_argument('report_file', type=str, help='A file to save report style results to.')

    args = parser.parse_args()

    if args.output_file:
        global output_file
        output_file = args.output_file

    with open(args.dump_file, "r") as raw_dump_file:
        raw_dump_file_list = raw_dump_file.read().split()
    
    hash_line_list = []

    for line in raw_dump_file_list:
        if line.endswith(":::"):
            hash_line_list.append(line)

    lm_accounts = identify_lm(hash_line_list)

    accounts_same_pass = compare_ntlm(hash_line_list)

    blank_accounts = blank_passwords(hash_line_list)

    with open(args.report_file, "w") as report_file:
        input = f"[+] Accounts with LM Hashes: {", ".join(lm_accounts)}\n"
        input += f"[+] Accounts with Blank Passwords: {", ".join(blank_accounts)}\n"
        input += "[+] Accounts with the Same Passwords:\n"
        for line in accounts_same_pass:
           input += f"\nSame Password: {line}"

        report_file.writelines(input)
    
    return

if __name__ == "__main__":
    main()