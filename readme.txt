Script Creator: Devin Patel
Last Updated: 20250822

Description:
    This script searches exploit information from the ExploitDB gitlab repo using CVEs as the search term.
    Information is output in a CSV file.

    Requirements:
        ->  A connection to the internet to clone and update ExploitDB repo (recommended to update once a day)
        ->  "git" is installed and on the PATH

Execution:
    $ python3 searchsploit.py

Usage:
    searchsploit.py [-h] [-o OUT] [-u] [-U] [-f FILE] [--cve CVE [CVE ...]]

    options:
        -h, --help           show this help message and exit
        -o, --out OUT        Output file path. Will output to current directory by default.
        -u, --update         Updates exploitdb prior to execution.
        -U, --update-only    Updates exploitdb then immediately exits.
        -f, --file FILE      A file of CVE IDs separated by newlines.
        --cve CVE [CVE ...]  A list of CVE IDs to search. These will be searched in addition to a --file input.
                                Example: --cve CVE-2022-24810 CVE-2022-24809

Dependencies:
    No external modules required.
