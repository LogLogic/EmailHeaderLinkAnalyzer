# EmailHeaderLinkAnalyzer
## Email Header & Link Analyzer

A Python script to analyze email files for phishing and security indicators, including SPF/DKIM checks, VirusTotal URL scanning, redirect analysis, and WHOIS lookups.

---
## Features

- Parses email headers and body
- Extracts URLs from the email content
- Checks SPF and DKIM authentication results
- Detects domain mismatches and suspicious keywords
- Submits URLs to VirusTotal for malware/suspicious detection
- Checks URL redirects
- Performs WHOIS lookups for domain registration info
- Generates a detailed report saved as `report.txt`

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
