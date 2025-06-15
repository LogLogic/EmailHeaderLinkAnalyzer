# EmailHeaderLinkAnalyzer
# Email Header & Link Analyzer

A Python-based security tool to analyze email headers and embedded links for signs of phishing, spoofing, and suspicious behavior. Designed for SOC analysts, security researchers, and anyone investigating suspicious emails.

---

## Features

-  **Header Parsing**: Extracts common fields (`From`, `To`, `Subject`, `Received`) from raw email files.
-  **SPF/DKIM Detection**: Checks sender authentication from `Authentication-Results`.
-  **Sender IP Extraction**: Pulls sender IP address from `Received` headers.
-  **Domain Mismatch Detection**: Compares sender domain with linked domains.
-  **VirusTotal Lookup**: Scans URLs using the VirusTotal public API.
-  **Redirect Checker**: Identifies hidden redirections in embedded links.
-  **WHOIS Lookup**: Fetches domain creation dates (optional).
-  **Keyword Phishing Detection**: Flags links using common phishing bait terms.
-  **Detailed Report Generation**: Outputs a human-readable `.txt` report.

---

## Setup

### 1. Clone the Repository

### 2. Install Dependencies
pip install -r requirements.txt

### 3. Add Your VirusTotal API Key
Create a config.py file: 
VT_API_KEY = "your_virustotal_api_key_here"

### 4. Enable WHOIS
To use WHOIS lookups, install the optional dependency:
pip install python-whois

---

## Folder Structure

email-header-link-analyzer/
├── analyzer/              # Core analysis modules
│   ├── email_parser.py
│   ├── link_checker.py
│   ├── vt_lookup.py
│   ├── whois_check.py
│   └── utils.py
├── data/                  # Raw email samples
│   └── samples/
├── tests/                 # Unit tests
├── config.py              # API keys (excluded from Git)
├── main.py                # CLI entry point
├── requirements.txt
├── .gitignore
└── README.md

