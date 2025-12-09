#!/usr/bin/env python3

import os
import sys
import shutil
import re
import csv
import argparse
import traceback
import requests
import subprocess

# Vars
exploitdb_exploits_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
exploitdb_shellcodes_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_shellcodes.csv"
exploitdb_dir = os.path.join(os.getcwd(), 'exploitdb')

# Funcs
def update_searchsploit():
    console("Updating \'exploitdb\' exploit list...", type='info')
    
    # Remove directory and fetch again
    if os.path.isdir(exploitdb_dir):
        shutil.rmtree(exploitdb_dir, ignore_errors=True)
        
    return fetch_exploitdb()

def fetch_exploitdb():
    rc = 0
    
    # Create exploitdb folder
    if not os.path.isdir(exploitdb_dir):
        os.makedirs(exploitdb_dir)
    
    # Use requests to get the raw file data
    for url in [exploitdb_exploits_url, exploitdb_shellcodes_url]:
        try:
            filename = os.path.join(exploitdb_dir, url.split("/")[-1])
            r = requests.get(url)
            r.raise_for_status()
            with open(filename, "wb") as f:
                f.write(r.content)
            console(f"Downloaded {os.path.basename(filename)}", type='info')
        except requests.HTTPError:
            console(f"There were problems encountered with trying to download the exploitdb file \"{os.path.basename(filename)}\"", type='error')
            rc = 1
    return rc
            

def searchsploit_csv(cves, search_data):
    output_data = []
    
    # Search Tags column for the CVE
    for i, cve in enumerate(cves, start=1):
        progress_bar(i, len(cves), prefix=f'Searching CVEs'.rjust(18), length=len(cves), suffix=f":: {cve}".ljust(20))
        for row in search_data:
            out_row = {}
            if row['codes'] is not None and cve in row['codes']:
                out_row = {
                    "CVE": f"CVE-{cve}",
                    "Title": row["description"],
                    "ID": row["id"],
                    "Date Published": row["date_published"],
                    "Date Added": row["date_added"],
                    "Date Updated": row["date_updated"],
                    "Type": row["type"],
                    "Platform": row["platform"],
                    "URL": "https://www.exploit-db.com/exploits/{}".format(row["id"])
                    }
                output_data.append(out_row)
    
    return output_data
    
def load_csv_data(path):
    data = []
    if os.path.isfile(path):
        with open(path, 'r', encoding='utf-8-sig') as r:
            reader = csv.DictReader(r)
            for row in reader:
                data.append(row)
    else:
        console(f'File {path} does not exist.', type='critical')
        sys.exit(1)
    if len(data) <= 0:
        console(f'File {path} did not import any data.', type='critical')
        sys.exit(1)
    return data

def write_csv_data(outfile, data, headers):
    rc = 1
    try:
        # Open outfile, wait if it is locked by something else
        _fp = None
        while True:
            try:
                _fp = open(outfile, 'w', newline='')
                break
            except PermissionError:
                input(f"\n[ERROR]  Outfile \"{outfile}\" cannot be opened. To continue, please make sure the file is not already open in another program.\nPress Enter to continue or CTRL+C to quit...")
                print()
        
        # Write data
        writer = csv.DictWriter(_fp, fieldnames=headers)
        writer.writeheader()
        
        for row in data:
            writer.writerow(row)
            
        rc = 0
        
    except:
        console("Unknown exception has occurred.", type='error')
        console(traceback.format_exc(), type='error')
        rc = 1
    finally:
        if _fp is not None and not _fp.closed:
            _fp.close()
        return rc

def ask(prompt_text, default=True):
    y = 'Y' if default else 'y'
    n = 'N' if not default else 'n'
    while True:
        uinput = input(f"{prompt_text}\n({y}/{n}): ").strip().lower()
        if len(uinput) == 0:
            return default
        elif uinput in ['y', 'yes', 'yuh', 'uh-huh']: return True
        elif uinput in ['n', 'no', 'nah', 'nuh-uh']: return False
        else:
            print("\n[ERROR]  Invalid input. Please enter yes or no. (Leave blank for {})".format('\"yes\"' if default else '\"no\"'))

def console(msg, type='info', newline=False):
    tag = f'[{type.upper()}]'
    if newline: '\n' + tag
    print(f'{tag.ljust(12)}  {msg}')

def progress_bar(iteration, total, prefix='', suffix='', decimals=2, length=50, fill='█', unfill='-', print_end="\r"):
    percent = ("{} / {}").format(iteration, total)
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + unfill * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent} {suffix}', end=print_end)

    # Print new line on complete
    if iteration >= total:
        print()

def main():
    help_description = """
This script searches exploit information from the official ExploitDB gitlab repo using CVEs as the search term.
Information is output in a CSV file.

Requirements:
    ->  A connection to the internet to fetch the exploit list from the ExploitDB gitlab repo (recommended to update once a day)
"""

    parser = argparse.ArgumentParser(description=help_description, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-o', '--out', type=str, default='searchsploit_results.csv', help='Output file path. Will output to current directory by default.')
    parser.add_argument('-u', '--update', action='store_true', help='Updates exploitdb prior to execution.')
    parser.add_argument('-U', '--update-only', dest="update_only", action='store_true', help='Updates exploitdb then immediately exits.')
    parser.add_argument('-f', '--file', type=str, help='A file of CVE IDs separated by newlines.')
    parser.add_argument('--cve', type=str, nargs='+', help='A list of CVE IDs to search. These will be searched in addition to a --file input.\n    Example: --cve CVE-2022-24810 CVE-2022-24809')

    args = parser.parse_args()

    # Input parsing
    outfile = 'searchsploit_results.csv'
    fieldnames = ['CVE', 'Title', 'ID', 'Type', 'Platform', 'Date Published', 'Date Added', 'Date Updated', 'URL']
    cve_list = []

    # Parse args
    if args.update is not None and args.update:
        rc = update_searchsploit()
        if rc != 0:
            sys.exit(rc)
    
    if args.update_only is not None and args.update_only:
        rc = update_searchsploit()
        sys.exit(rc)

    if args.cve is None and args.file is None:
        parser.print_usage()
        console('--cve or --file argument is required', type='error')
        sys.exit(1)

    if args.file is not None:
        with open(args.file, 'r') as r:
            cve_list += [l.strip().upper() for l in r.readlines()]

    if args.cve is not None:
        cve_list += [l.strip().upper() for l in args.cve]

    # Check if every CVE is correctly formatted
    t_cve_list = []
    for cve in cve_list:
        # First, ensure it is the properly formatted and extract the numbers after CVE
        if (m := re.match(r'^CVE-(\d{4}-\d+)$', cve)):
            t_cve_list.append(m.group(1))
        else:
            print(f"[ERROR]  Entry \"{cve}\" is not a CVE. This will result in unprecedented searchsploit results.")
            rv = ask(   "         Do you still want to include it as-is?", default=False)
            print()
            if rv:
                t_cve_list.append(cve)
            else: continue
    cve_list = t_cve_list

    if args.out is not None:
        outfile = args.out
        if os.path.splitext(outfile)[1] != '.csv':
            outfile += '.csv'

    # Check if exploitdb repo is cloned
    if not os.path.isdir(exploitdb_dir):
        console('Repo \'exploitdb\' not found. Attempting to clone now...', type='info')
        fetch_exploitdb()

    # Load the data
    exploits_csv = os.path.join(exploitdb_dir, 'files_exploits.csv')
    exploits_data = load_csv_data(exploits_csv)

    shellcodes_csv = os.path.join(exploitdb_dir, 'files_shellcodes.csv')
    shellcodes_data = load_csv_data(shellcodes_csv)
    
    # Ensure data is loaded
    if len(exploits_data) <= 0:
        console("Improperly loaded data from \"files_exploits.csv.\"")
        sys.exit(1)
    if len(shellcodes_data) <= 0:
        console("Improperly loaded data from \"files_shellcodes.csv.\"")
        sys.exit(1)

    searchable_data = exploits_data + shellcodes_data

    # Time to process the CVEs
    output_data = searchsploit_csv(cve_list, searchable_data)

    rc = write_csv_data(outfile, output_data, fieldnames)
    if rc != 0:
        sys.exit(rc)
    console(f"Searchsploit complete. Results output to {outfile}", type='success')
    return

if __name__ == '__main__':
    try:
        main()
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)
    except SystemExit as se:
        sys.exit(se.code)
    except:
        console("Unknown exception has been thrown.", type='error')
        console(traceback.format_exc(), type='error')
        sys.exit(1)
