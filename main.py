import time
import re
import requests
import sys
import os
import logging
from urllib.parse import urlparse

# Import whois module for domain information; if not installed, set to None
try:
    import whois
except ImportError:
    whois = None

# Configure logging: show time, log level, and message
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Load VirusTotal API key from environment variable for security
VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    logging.error("Environment variable VT_API_KEY not set.")
    sys.exit(1)  # Exit if API key is missing

def check_url_virustotal(url):
    """
    Submit a URL to VirusTotal for scanning and get the analysis result.
    Returns JSON response with scan details or None if error.
    """
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}

    try:
        # Submit URL for scanning
        submit_resp = requests.post(api_url, headers=headers, data={"url": url})
        if submit_resp.status_code != 200:
            logging.error(f"Failed to submit URL to VirusTotal: {submit_resp.status_code}")
            return None

        # Extract scan ID from submission response
        scan_id = submit_resp.json()["data"]["id"]

        # Wait for VirusTotal to process the scan (approximate)
        time.sleep(15)

        # Fetch the scan report using scan ID
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        report_resp = requests.get(report_url, headers=headers)

        return report_resp.json() if report_resp.status_code == 200 else None

    except Exception as e:
        logging.exception(f"VirusTotal error: {e}")
        return None

def extract_spf_dkim(auth_results):
    """
    Extract SPF and DKIM results from the Authentication-Results email header.
    Returns tuple (spf_result, dkim_result) as lowercase strings or None if not found.
    """
    spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
    dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
    return spf_match.group(1).lower() if spf_match else None, dkim_match.group(1).lower() if dkim_match else None

def extract_email_headers(file_path):
    """
    Read the email file and extract the headers into a dictionary.
    Stops reading headers at the first empty line (header/body separator).
    """
    headers = {}
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line == "":  # End of headers
                break
            if ':' in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers

def extract_email_body(file_path):
    """
    Read the email file and extract the body (after the headers).
    Returns the body as a single concatenated string.
    """
    with open(file_path, 'r') as file:
        lines = file.readlines()

    header_ended = False
    # Include lines only after the first empty line indicating end of headers
    return "".join(line for line in lines if header_ended or (header_ended := line.strip() == ""))

def extract_sender_ip(headers):
    """
    Extract the sender IP address from the last 'Received' header.
    Returns the IP address as a string or a message if not found.
    """
    # Gather all 'Received' header values (case-insensitive)
    received_headers = [v for k, v in headers.items() if k.lower() == 'received']
    if not received_headers:
        return "No Received headers found"

    last_received = received_headers[-1]
    # Match IP inside square brackets first
    ip_match = re.search(r'\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]', last_received)
    if not ip_match:
        # Fallback: match any IPv4 address pattern
        ip_match = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})', last_received)
    return ip_match.group(1) if ip_match else "IP not found"

def check_redirect(url):
    """
    Check if the given URL redirects to a different domain.
    Returns a tuple (final_url, redirected_flag).
    If error occurs, returns (None, False).
    """
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        orig_domain = urlparse(url).netloc
        final_domain = urlparse(response.url).netloc
        return (response.url, orig_domain != final_domain)
    except Exception as e:
        logging.warning(f"Redirect check failed for {url}: {e}")
        return (None, False)

def check_domain_whois(domain):
    """
    Perform WHOIS lookup for the domain to get creation date or other info.
    Returns creation date as string or error message if WHOIS is not available.
    """
    if not whois:
        return "❌ WHOIS not installed"
    try:
        w = whois.whois(domain)
        return str(w.creation_date)
    except Exception as e:
        return f"❌ WHOIS error: {e}"

def analyze_email(file_path, output_path="report.txt"):
    """
    Main function to analyze the email file:
    - Extract headers and body
    - Find URLs in the body
    - Check SPF/DKIM results
    - Check domain mismatches
    - Query VirusTotal for URLs
    - Look for suspicious keywords in domains
    - Check redirects
    - Perform WHOIS lookups
    - Save a report to output_path
    """
    report = []

    # Extract headers and body from the email file
    headers = extract_email_headers(file_path)
    body = extract_email_body(file_path)

    # Extract all URLs from the email body
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)

    # Header information summary
    report.append("=== Email Header Info ===")
    report.append(f"From: {headers.get('From', 'N/A')}")
    report.append(f"To: {headers.get('To', 'N/A')}")
    report.append(f"Subject: {headers.get('Subject', 'N/A')}")
    report.append(f"Received: {headers.get('Received', 'N/A')}")
    sender_ip = extract_sender_ip(headers)
    report.append(f"Sender IP: {sender_ip}\n")

    # Extract and report SPF and DKIM results
    spf, dkim = extract_spf_dkim(headers.get('Authentication-Results', ''))
    report.append(f"SPF Result: {spf if spf else 'Not Found'}")
    report.append(f"DKIM Result: {dkim if dkim else 'Not Found'}\n")

    # Domain mismatch check between sender domain and URLs found
    report.append("=== Domain Mismatch Check ===")
    match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', headers.get('From', ''))
    sender_domain = match.group(1) if match else None
    if sender_domain:
        for url in urls:
            domain = urlparse(url).netloc
            result = "⚠️ Mismatch" if sender_domain not in domain else "✅ Match"
            report.append(f"{result}: {domain} vs {sender_domain}")
    else:
        report.append("Could not extract sender domain.")

    # VirusTotal scanning of each URL found in the email body
    report.append("\n=== VirusTotal Scan ===")
    for url in urls:
        clean_url = url.split('#')[0]  # Remove fragment identifier if present
        logging.info(f"Checking with VirusTotal: {clean_url}")
        result = check_url_virustotal(clean_url)
        if result is None:
            report.append("❌ Could not get result.")
        else:
            stats = result["data"]["attributes"]["stats"]
            report.append(f"✅ VT → Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}")

    # Check for suspicious keywords in domain names to catch phishing attempts
    report.append("\n=== Domain Keyword Check ===")
    phishing_keywords = {
        "paypal": "paypal.com",
        "amazon": "amazon.com",
        "bank": None,  # Generic suspicious keyword without legit domain
    }

    for url in urls:
        domain = urlparse(url).netloc.lower()
        for word, legit in phishing_keywords.items():
            if word in domain:
                if legit and not domain.endswith(legit):
                    report.append(f"⚠️ '{domain}' contains '{word}' but is not {legit}")
                elif not legit:
                    report.append(f"⚠️ Suspicious keyword '{word}' found in {domain}")

    # Redirect checks for all URLs to detect suspicious redirections
    report.append("\n=== Redirect Check ===")
    for url in urls:
        final_url, redirected = check_redirect(url)
        if final_url:
            report.append(f"🔍 {url} → {final_url}")
            if redirected:
                report.append("⚠️ Redirected to a different domain!")
            else:
                report.append("✅ No suspicious redirect.")
        else:
            report.append(f"❌ Could not check {url}")

    # WHOIS checks for domain registration information
    report.append("\n=== WHOIS Check ===")
    for url in urls:
        domain = urlparse(url).netloc
        whois_info = check_domain_whois(domain)
        report.append(f"{domain}: {whois_info}")

    # Save the full report to a file in the current working directory
    output_path = os.path.join(os.getcwd(), "report.txt")
    with open(output_path, "w") as f:
        f.write("\n".join(report))

    logging.info(f"📄 Report saved to {output_path}")
    logging.info("✅ Analysis complete.")

# Script entry point. Run analysis if email file path is provided
if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error("Usage: python main.py path_to_email_file")
    else:
        analyze_email(sys.argv[1])
