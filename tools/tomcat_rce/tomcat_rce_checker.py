#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
import urllib3
import concurrent.futures
from colorama import init, Fore
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

class TomcatRCEChecker:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.vulnerable = False
        self.session = requests.Session()
        self.session.verify = False
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def print_status(self, message, status="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if status == "INFO":
            print(f"{Fore.BLUE}[{timestamp}] INFO: {message}{Fore.RESET}")
        elif status == "SUCCESS":
            print(f"{Fore.GREEN}[{timestamp}] SUCCESS: {message}{Fore.RESET}")
        elif status == "ERROR":
            print(f"{Fore.RED}[{timestamp}] ERROR: {message}{Fore.RESET}")
        elif status == "WARNING":
            print(f"{Fore.YELLOW}[{timestamp}] WARNING: {message}{Fore.RESET}")

    def check_version(self):
        """Check Tomcat version"""
        try:
            response = self.session.get(f"{self.target}/", headers=self.headers, timeout=10)
            if "Apache Tomcat" in response.text:
                self.print_status(f"Found Apache Tomcat server", "SUCCESS")
                # Extract version if possible
                if "Apache Tomcat/10.1.28" in response.text:
                    self.print_status("Target is running Apache Tomcat 10.1.28", "WARNING")
                    return True
            return False
        except Exception as e:
            self.print_status(f"Error checking version: {str(e)}", "ERROR")
            return False

    def check_manager_app(self):
        """Check if manager application is accessible"""
        try:
            response = self.session.get(f"{self.target}/manager/html", headers=self.headers, timeout=10)
            if response.status_code == 401:
                self.print_status("Manager application found (requires authentication)", "WARNING")
                return True
            elif response.status_code == 200:
                self.print_status("Manager application found and accessible!", "WARNING")
                return True
            return False
        except Exception as e:
            self.print_status(f"Error checking manager app: {str(e)}", "ERROR")
            return False

    def check_ghostcat(self):
        """Check for Ghostcat vulnerability (CVE-2020-1938)"""
        try:
            # This is a simplified check - real exploitation would require AJP protocol
            response = self.session.get(f"{self.target}/docs/", headers=self.headers, timeout=10)
            if "Apache Tomcat" in response.text and "10.1.28" in response.text:
                self.print_status("Server might be vulnerable to Ghostcat (CVE-2020-1938)", "WARNING")
                return True
            return False
        except Exception as e:
            self.print_status(f"Error checking Ghostcat: {str(e)}", "ERROR")
            return False

    def check_war_upload(self):
        """Check for WAR file upload vulnerability"""
        try:
            # Check common paths for file upload
            paths = [
                "/manager/html/upload",
                "/manager/deploy",
                "/manager/upload"
            ]
            for path in paths:
                response = self.session.get(f"{self.target}{path}", headers=self.headers, timeout=10)
                if response.status_code != 404:
                    self.print_status(f"Potential file upload endpoint found at {path}", "WARNING")
                    return True
            return False
        except Exception as e:
            self.print_status(f"Error checking WAR upload: {str(e)}", "ERROR")
            return False

    def check_default_credentials(self):
        """Check for default credentials"""
        default_creds = [
            ('tomcat', 'tomcat'),
            ('admin', 'admin'),
            ('admin', 'tomcat'),
            ('tomcat', 'admin'),
            ('role1', 'role1'),
            ('role', 'changethis'),
            ('tomcat', 's3cret'),
            ('admin', 'password')
        ]
        
        for username, password in default_creds:
            try:
                response = self.session.get(
                    f"{self.target}/manager/html",
                    auth=(username, password),
                    headers=self.headers,
                    timeout=10
                )
                if response.status_code == 200:
                    self.print_status(f"Found working credentials: {username}:{password}", "SUCCESS")
                    return True
            except Exception as e:
                if self.verbose:
                    self.print_status(f"Error checking credentials {username}:{password}: {str(e)}", "ERROR")
                continue
        return False

    def check_all_vulnerabilities(self):
        """Run all vulnerability checks"""
        self.print_status(f"Starting vulnerability scan for {self.target}", "INFO")
        
        checks = [
            (self.check_version, "Version Check"),
            (self.check_manager_app, "Manager Application Check"),
            (self.check_ghostcat, "Ghostcat Vulnerability Check"),
            (self.check_war_upload, "WAR Upload Check"),
            (self.check_default_credentials, "Default Credentials Check")
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_check = {executor.submit(check[0]): check[1] for check in checks}
            for future in concurrent.futures.as_completed(future_to_check):
                check_name = future_to_check[future]
                try:
                    result = future.result()
                    if result:
                        self.vulnerable = True
                except Exception as e:
                    self.print_status(f"Error in {check_name}: {str(e)}", "ERROR")

        if self.vulnerable:
            self.print_status("Target might be vulnerable to one or more RCE vulnerabilities!", "WARNING")
        else:
            self.print_status("No obvious vulnerabilities found", "INFO")

def main():
    parser = argparse.ArgumentParser(description='Apache Tomcat RCE Vulnerability Checker')
    parser.add_argument('-t', '--target', required=True, help='Target URL (e.g., http://example.com:8080)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    try:
        checker = TomcatRCEChecker(args.target, args.verbose)
        checker.check_all_vulnerabilities()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 