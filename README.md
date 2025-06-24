# EmailHeaderLinkAnalyzer
## Email Header & Link Analyzer

A Python script to analyze email files for phishing and security indicators, including SPF/DKIM checks, VirusTotal URL scanning, redirect analysis, and WHOIS lookups.

---
## Features

-  **Header Parsing**: Extracts common fields (From, To, Subject, Received) from raw email files.
-  **SPF/DKIM Detection**: Checks sender authentication from Authentication-Results.
-  **Sender IP Extraction**: Pulls sender IP address from Received headers.
-  **Domain Mismatch Detection**: Compares sender domain with linked domains.
-  **VirusTotal Lookup**: Scans URLs using the VirusTotal public API.
-  **Redirect Checker**: Identifies hidden redirections in embedded links.
-  **WHOIS Lookup**: Fetches domain creation dates (optional).
-  **Keyword Phishing Detection**: Flags links using common phishing bait terms.
-  **Detailed Report Generation**: Outputs a human-readable .txt report.

---
## Requirements

- Python 3.6+
- Modules: `requests`, `whois` (optional), `logging`
- VirusTotal API key (free sign-up at [VirusTotal](https://www.virustotal.com))

---
## Setup

1. Clone this repository
2. Install dependencies:
   pip install requests python-whois
3. Set your VirusTotal API key as an environment variable:
   export VT_API_KEY="your_actual_api_key_here"

---
## Usage
Run the script with an email file as argument:
python3 main.py samples/sample_email.txt

The script will analyze the email and save a report.txt file in the current directory.
