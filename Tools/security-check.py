#!/usr/bin/env python3
import urllib.request
import urllib.error
import sys
import time

# Configuration
TARGET_URL = "http://127.0.0.1:80"

# UI Colors
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def print_status(test_name, result, detail=""):
    color = GREEN if result == "PASS" else RED
    print(f"[{color}{result}{RESET}] {test_name:<45} {detail}")

def check_url(path, description, expected_code=403):
    url = f"{TARGET_URL}{path}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req) as response:
            code = response.getcode()
            if code == expected_code:
                print_status(description, "PASS", f"(Got {code})")
            else:
                print_status(description, "FAIL", f"(Expected {expected_code}, Got {code})")
    except urllib.error.HTTPError as e:
        if e.code == expected_code:
            print_status(description, "PASS", f"(Blocked with {e.code})")
        else:
            print_status(description, "FAIL", f"(Expected {expected_code}, Got {e.code})")
    except Exception as e:
        print(f"{RED}[!] Error connecting: {e}{RESET}")

def run_audit():
    print(f"\n{CYAN}--- Hybrid Elite v3.0 Security Audit ---{RESET}\n")
    
    # 1. Test .htaccess FilesMatch enforcement
    print(f"{YELLOW}>>> Testing .htaccess 'FilesMatch' Blocking{RESET}")
    check_url("/.env", "Block .env (Parsed from .htaccess)")
    check_url("/logs.db", "Block .db (Parsed from .htaccess)")
    check_url("/config.ini", "Block .ini (Parsed from .htaccess)")
    check_url("/server.py", "Block server source code")
    check_url("/backup.sql", "Block .sql backups")

    # 2. Test Options -Indexes enforcement
    print(f"\n{YELLOW}>>> Testing .htaccess 'Options -Indexes'{RESET}")
    # We test a directory that exists but has no index file to see if listing is blocked
    check_url("/db/", "Block Directory Listing", expected_code=403)

    # 3. Test Iframe Compatibility (Important for ljfragrances.uk)
    print(f"\n{YELLOW}>>> Testing Iframe Accessibility{RESET}")
    try:
        with urllib.request.urlopen(TARGET_URL) as response:
            headers = response.headers
            xfo = headers.get("X-Frame-Options")
            csp = headers.get("Content-Security-Policy")
            
            if not xfo and not csp:
                print_status("Iframe Friendly (No blocking headers)", "PASS")
            else:
                print_status("Iframe Friendly", "FAIL", f"Found blocking headers: {xfo or ''} {csp or ''}")
                
            # Check for 2026 standard headers that SHOULD be there
            nosniff = headers.get("X-Content-Type-Options")
            if nosniff == "nosniff":
                print_status("MIME Protection (X-Content-Type-Options)", "PASS")
            else:
                print_status("MIME Protection", "FAIL", "Missing 'nosniff' header")
                
    except Exception as e:
        print(f"Header Check Failed: {e}")

    print(f"\n{CYAN}--- Audit Complete ---{RESET}\n")

if __name__ == "__main__":
    run_audit()