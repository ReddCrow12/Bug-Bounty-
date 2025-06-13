#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
import urllib3
import concurrent.futures
from colorama import init, Fore
from datetime import datetime
from urllib.parse import urlparse
import socket
import re
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

class TomcatFinder:
    def __init__(self, verbose=False, threads=10, timeout=10):
        self.verbose = verbose
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.found_tomcats = []

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

    def normalize_url(self, url):
        """Normalize URL to include scheme if missing"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def check_tomcat_version(self, response_text):
        """Extract Tomcat version from response"""
        version_patterns = [
            r'Apache Tomcat/([0-9.]+)',
            r'Tomcat/([0-9.]+)',
            r'Server: Apache-Coyote/([0-9.]+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, response_text)
            if match:
                return match.group(1)
        return None

    def check_common_paths(self, base_url):
        """Check common Tomcat paths"""
        paths = [
            '/',
            '/manager/html',
            '/host-manager/html',
            '/docs/',
            '/examples/',
            '/ROOT/',
            '/tomcat/',
            '/tomcat-docs/'
        ]
        
        for path in paths:
            try:
                url = base_url + path
                response = self.session.get(url, headers=self.headers, timeout=self.timeout)
                if response.status_code != 404:
                    if 'Apache Tomcat' in response.text or 'Tomcat' in response.text:
                        version = self.check_tomcat_version(response.text)
                        return True, version, path
            except:
                continue
        return False, None, None

    def check_ajp_port(self, hostname):
        """Check if AJP port (8009) is open"""
        try:
            ip = socket.gethostbyname(hostname)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, 8009))
            sock.close()
            return result == 0
        except:
            return False

    def check_domain(self, domain):
        """Check a single domain for Tomcat"""
        try:
            # Normalize domain
            domain = domain.strip()
            if not domain:
                return
            
            base_url = self.normalize_url(domain)
            parsed = urlparse(base_url)
            hostname = parsed.netloc.split(':')[0]

            if self.verbose:
                self.print_status(f"Checking {domain}", "INFO")

            # Check common paths
            is_tomcat, version, path = self.check_common_paths(base_url)
            
            if is_tomcat:
                # Check AJP port
                ajp_open = self.check_ajp_port(hostname)
                
                # Get server info
                try:
                    response = self.session.get(base_url, headers=self.headers, timeout=self.timeout)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.title.string if soup.title else "No title"
                except:
                    title = "Could not get title"

                # Store results
                result = {
                    'domain': domain,
                    'version': version,
                    'path': path,
                    'ajp_open': ajp_open,
                    'title': title
                }
                self.found_tomcats.append(result)
                
                # Print results
                status = "SUCCESS" if ajp_open else "WARNING"
                self.print_status(
                    f"Found Tomcat {version} at {domain}{path} (AJP: {'Open' if ajp_open else 'Closed'})",
                    status
                )
                if self.verbose:
                    self.print_status(f"Title: {title}", "INFO")

        except Exception as e:
            if self.verbose:
                self.print_status(f"Error checking {domain}: {str(e)}", "ERROR")

    def process_domains(self, domains):
        """Process list of domains"""
        self.print_status(f"Starting scan with {self.threads} threads", "INFO")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_domain, domains)
        
        # Print summary
        self.print_status("\nScan Summary:", "INFO")
        self.print_status(f"Total domains checked: {len(domains)}", "INFO")
        self.print_status(f"Found Tomcat servers: {len(self.found_tomcats)}", "INFO")
        
        if self.found_tomcats:
            self.print_status("\nVulnerable servers (AJP port open):", "WARNING")
            for tomcat in self.found_tomcats:
                if tomcat['ajp_open']:
                    self.print_status(
                        f"Domain: {tomcat['domain']}\n"
                        f"Version: {tomcat['version']}\n"
                        f"Path: {tomcat['path']}\n"
                        f"Title: {tomcat['title']}\n",
                        "WARNING"
                    )

def main():
    parser = argparse.ArgumentParser(description='Tomcat Server Finder')
    parser.add_argument('-i', '--input', required=True, help='Input file containing domains (one per line)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    try:
        # Read domains from file
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]

        # Initialize finder
        finder = TomcatFinder(verbose=args.verbose, threads=args.threads)
        
        # Process domains
        finder.process_domains(domains)
        
        # Save results if output file specified
        if args.output and finder.found_tomcats:
            with open(args.output, 'w') as f:
                for tomcat in finder.found_tomcats:
                    f.write(f"Domain: {tomcat['domain']}\n")
                    f.write(f"Version: {tomcat['version']}\n")
                    f.write(f"Path: {tomcat['path']}\n")
                    f.write(f"AJP Open: {tomcat['ajp_open']}\n")
                    f.write(f"Title: {tomcat['title']}\n")
                    f.write("-" * 50 + "\n")
            finder.print_status(f"Results saved to {args.output}", "SUCCESS")

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 