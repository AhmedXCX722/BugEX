import requests
import re
import sys
from urllib.parse import urljoin
from bs4 import BeautifulSoup

def banner():
    print(r"""
    ____             ______  __  __  
   |  _ \           |  ____| \ \/ /  
   | |_) | ___  ___ | |__     \  /   
   |  _ < / _ \/ _ \|  __|    /  \   
   | |_) |  __/ (_) | |____  /_/\_\  
   |____/ \___|\___/|______|         
                                    
        🐞 BugEX - The Bug Bounty Toolkit ⚡
              Version: 1.0
    """)

# Call the banner function at the start of your script
banner()

# PyBounty v1.0 by Harpy 🦅
# The ultimate bug bounty tool for ethical hackers
# Use this script with caution, handle responsibly 🔥

# Headers for request to look legit
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0"
}

# Function to perform SQL Injection
def sql_injection(url):
    print(f"[🔥] Testing SQL Injection on {url}")
    sqli_payloads = ["' OR '1'='1", "' OR '1'='0", "' OR '1'='1' -- "]
    for payload in sqli_payloads:
        vulnerable_url = f"{url}{payload}"
        response = requests.get(vulnerable_url, headers=headers)
        if "error" in response.text or "syntax" in response.text:
            print(f"[✅] Possible SQL Injection Vulnerability Found: {vulnerable_url}")
            return vulnerable_url
    print(f"[❌] No SQL Injection vulnerability found on {url}")

# Function to perform Cross-Site Scripting (XSS)
def xss_injection(url):
    print(f"[🔥] Testing XSS on {url}")
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
    for payload in xss_payloads:
        vulnerable_url = f"{url}?search={payload}"
        response = requests.get(vulnerable_url, headers=headers)
        if payload in response.text:
            print(f"[✅] XSS Vulnerability Found: {vulnerable_url}")
            return vulnerable_url
    print(f"[❌] No XSS vulnerability found on {url}")

# Function to test Cross-Site Request Forgery (CSRF)
def csrf_test(url):
    print(f"[🔥] Testing CSRF on {url}")
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        if not form.find("input", {"type": "hidden", "name": "csrf_token"}):
            print(f"[✅] CSRF vulnerability found in form on {url}")
            return True
    print(f"[❌] No CSRF vulnerability found on {url}")
    return False

# Function to brute-force directories
def dir_bruteforce(url):
    print(f"[🔥] Starting directory brute-force on {url}")
    common_paths = ["/admin", "/login", "/dashboard", "/config", "/backup"]
    for path in common_paths:
        full_url = urljoin(url, path)
        response = requests.get(full_url, headers=headers)
        if response.status_code == 200:
            print(f"[✅] Found directory: {full_url}")
        else:
            print(f"[❌] Not found: {full_url}")

# Function to scan for subdomains
def subdomain_scan(domain):
    print(f"[🔥] Starting subdomain enumeration for {domain}")
    subdomains = ["admin", "mail", "dev", "test", "api"]
    found_subdomains = []
    for sub in subdomains:
        subdomain_url = f"http://{sub}.{domain}"
        try:
            response = requests.get(subdomain_url, headers=headers)
            if response.status_code == 200:
                print(f"[✅] Subdomain found: {subdomain_url}")
                found_subdomains.append(subdomain_url)
        except requests.ConnectionError:
            print(f"[❌] Subdomain not found: {subdomain_url}")
    return found_subdomains

# Function to perform port scanning
def port_scan(target):
    print(f"[🔥] Starting port scan on {target}")
    open_ports = []
    for port in range(20, 100):  # Scanning ports 20-100 for simplicity
        try:
            response = requests.get(f"{target}:{port}", headers=headers)
            if response.status_code == 200:
                print(f"[✅] Open port found: {port}")
                open_ports.append(port)
        except:
            pass
    return open_ports

# Function to generate a report
def generate_report(vulns):
    print(f"\n[💀] Vulnerabilities Found:\n{'-'*30}")
    for vuln in vulns:
        print(f"- {vuln}")

# Main function to run the tool
def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    vulnerabilities = []

    print(f"\n[🔎] Scanning {target_url} for vulnerabilities...\n")

    # Running various tests
    if sql_injection(target_url):
        vulnerabilities.append("SQL Injection")
    
    if xss_injection(target_url):
        vulnerabilities.append("XSS Vulnerability")

    if csrf_test(target_url):
        vulnerabilities.append("CSRF Vulnerability")

    dir_bruteforce(target_url)

    subdomains = subdomain_scan(target_url)
    if subdomains:
        vulnerabilities.append(f"Subdomains found: {', '.join(subdomains)}")

    open_ports = port_scan(target_url)
    if open_ports:
        vulnerabilities.append(f"Open ports: {', '.join(map(str, open_ports))}")

    # Generate a report of findings
    if vulnerabilities:
        generate_report(vulnerabilities)
    else:
        print(f"[✅] No vulnerabilities found!")

if __name__ == "__main__":
    main()
