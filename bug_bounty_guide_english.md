# 🐛 Comprehensive Bug Bounty Guide 🐛

## 📋 Table of Contents
- [Introduction](#introduction)
- [Essential Tools](#essential-tools)
- [Reconnaissance Methods](#reconnaissance-methods)
- [Testing Checklist](#testing-checklist)
- [Finding Targets for Beginners](#finding-targets-for-beginners)
- [Common Vulnerability Types](#common-vulnerability-types)
- [Recommended Tool Commands](#recommended-tool-commands)

## Introduction
This guide provides comprehensive information on tools, methods, and techniques for bug bounty hunting. The guide is suitable for both beginners and advanced practitioners.

## Essential Tools

### 🛠️ Scanning and Mapping Tools
- **Nmap** - Port scanning and service identification
- **Subfinder** - Subdomain discovery
- **Katana** - Advanced subdomain crawling
- **Waybackurls** - Historical URL discovery
- **FFuf** - Subdomain and directory fuzzing
- **Nuclei** - Automated vulnerability scanning
- **WPScan** - WordPress site scanning
- **SQLMap** - SQL Injection detection and exploitation

### 🔍 DNS Tools
- **Dig** - Advanced DNS queries
- **Whois** - Domain registration information
- **DNSRecon** - Comprehensive DNS mapping

## Reconnaissance Methods

### Phase 1: Information Gathering
1. Subdomain discovery
2. IP address collection
3. Port scanning
4. Technology identification
5. Entry point discovery

### Phase 2: Mapping
1. Entry point mapping
2. Functionality identification
3. Parameter discovery
4. API mapping

### Phase 3: Testing
1. Automated testing
2. Manual testing
3. Code analysis
4. Security testing

## Testing Checklist

### ✅ Basic Checks
- [ ] Subdomain scanning
  - Tool: **Subfinder**
  ```bash
  subfinder -d target.com -o subdomains.txt
  ```
  - Tool: **Amass**
  ```bash
  amass enum -passive -d target.com -o subdomains.txt
  ```

- [ ] Port scanning
  - Tool: **Nmap**
  ```bash
  nmap -sV -sC -p- target.com
  ```
  - Tool: **Masscan**
  ```bash
  masscan target.com -p1-65535 --rate=1000
  ```

- [ ] SSL/TLS testing
  - Tool: **Nmap**
  ```bash
  nmap -sV --script ssl-enum-ciphers -p 443 target.com
  ```
  - Tool: **TestSSL**
  ```bash
  testssl.sh target.com
  ```

- [ ] Technology identification
  - Tool: **Wappalyzer** (Browser extension)
  - Tool: **WhatWeb**
  ```bash
  whatweb -a 3 target.com
  ```

- [ ] Header testing
  - Tool: **Curl**
  ```bash
  curl -I -L target.com
  ```
  - Tool: **Nmap**
  ```bash
  nmap --script http-headers target.com
  ```

- [ ] Cookie testing
  - Tool: **Curl**
  ```bash
  curl -I -L -v target.com | grep -i "set-cookie"
  ```
  - Tool: **Burp Suite** (Manual testing)

- [ ] CORS testing
  - Tool: **Corsy**
  ```bash
  python3 corsy.py -u https://target.com
  ```
  - Tool: **Nmap**
  ```bash
  nmap --script http-cors target.com
  ```

- [ ] CSP testing
  - Tool: **Curl**
  ```bash
  curl -I -L target.com | grep -i "content-security-policy"
  ```
  - Tool: **CSP Evaluator** (Online tool)

### ✅ Advanced Checks
- [ ] XSS testing
- [ ] SQL Injection testing
- [ ] SSRF testing
- [ ] XXE testing
- [ ] RCE testing
- [ ] LFI/RFI testing
- [ ] IDOR testing
- [ ] CSRF testing

## Finding Targets for Beginners

### 🎯 Recommendations for Beginners
1. Start with platforms like:
   - HackerOne
   - Bugcrowd
   - Synack
2. Look for programs with:
   - Low difficulty rating
   - Reasonable rewards
   - Good support
3. Focus on basic vulnerabilities:
   - XSS
   - SQL Injection
   - CSRF
   - IDOR

## Common Vulnerability Types

### 🔥 Critical Vulnerabilities
1. **Remote Code Execution (RCE)**
   - Code vulnerability exploitation
   - Server vulnerability exploitation
   - Application vulnerability exploitation

2. **SQL Injection**
   - SQL injection
   - Parameter exploitation
   - Search form exploitation

3. **Cross-Site Scripting (XSS)**
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS

### 🎯 Medium Vulnerabilities
1. **Server-Side Request Forgery (SSRF)**
2. **XML External Entity (XXE)**
3. **Insecure Direct Object References (IDOR)**
4. **Cross-Site Request Forgery (CSRF)**

## Recommended Tool Commands

### Nmap
```bash
# Basic scan
nmap -sV -sC -p- target.com

# Aggressive scan
nmap -A -T4 -p- target.com

# SSL scan
nmap -sV --script ssl-enum-ciphers -p 443 target.com

# Vulnerability scan
nmap --script vuln target.com
```

### Subfinder
```bash
# Basic scan
subfinder -d target.com -o subdomains.txt

# Scan with additional sources
subfinder -d target.com -sources all -o subdomains.txt

# Recursive DNS scan
subfinder -d target.com -recursive -o subdomains.txt
```

### Nuclei
```bash
# Basic scan
nuclei -u target.com

# Scan with specific templates
nuclei -u target.com -t cves/

# Aggressive scan
nuclei -u target.com -severity critical,high -c 50
```

### SQLMap
```bash
# Parameter testing
sqlmap -u "http://target.com/page.php?id=1"

# Form testing
sqlmap -u "http://target.com/login.php" --forms

# Testing with cookies
sqlmap -u "http://target.com/page.php" --cookie="PHPSESSID=123"
```

### FFuf
```bash
# Subdomain fuzzing
ffuf -w wordlist.txt -u https://FUZZ.target.com

# Directory fuzzing
ffuf -w wordlist.txt -u https://target.com/FUZZ

# Fuzzing with headers
ffuf -w wordlist.txt -u https://target.com/FUZZ -H "Cookie: session=123"
```

### WPScan
```bash
# Basic scan
wpscan --url target.com

# Aggressive scan
wpscan --url target.com --enumerate p,t,u

# Scan with API
wpscan --url target.com --api-token YOUR_TOKEN
```

### Katana
```bash
# Basic scan
katana -u target.com

# Scan with filters
katana -u target.com -f "\.(php|asp|aspx|jsp)$"

# Scan with headers
katana -u target.com -H "Cookie: session=123"
```

### Dig
```bash
# A record query
dig target.com A

# MX record query
dig target.com MX

# TXT record query
dig target.com TXT

# NS record query
dig target.com NS
```

### Waybackurls
```bash
# Historical URL discovery
waybackurls target.com > urls.txt

# Discovery with filters
waybackurls target.com | grep "\.php"

# Discovery with parameters
waybackurls target.com | grep "="
```

## 🎯 Vulnerability Identification Signs

### SQL Injection
- SQL errors
- Different response times
- Unexpected behavior
- Suspicious error messages

### XSS
- JavaScript code returned
- HTML tags returned
- Parameters reflecting input
- JavaScript events

### SSRF
- Access to internal services
- Server errors
- Unexpected responses
- Access to sensitive information

### XXE
- XML errors
- File access
- Unexpected responses
- Server errors

## 📝 Important Tips

1. **Documentation**
   - Document every step in the process
   - Take screenshots
   - Save logs
   - Document PoC

2. **Ethics**
   - Don't damage systems
   - Don't steal information
   - Don't violate privacy
   - Maintain confidentiality

3. **Continuous Learning**
   - Follow updates
   - Read blogs
   - Participate in forums
   - Learn from community

## 🔄 When to Move to the Next Phase?

1. **Completed all basic checks**
2. **No basic vulnerabilities found**
3. **Deep understanding of the system**
4. **Successful PoC available**
5. **Vulnerability verified and documented**

## 📚 Additional Resources

### Recommended Blogs
- PortSwigger Web Security Blog
- OWASP
- HackerOne Blog
- Bugcrowd Blog

### Recommended Courses
- PortSwigger Web Security Academy
- OWASP WebGoat
- TryHackMe
- HackTheBox

### Additional Tools
- Burp Suite
- OWASP ZAP
- Metasploit
- Acunetix
- Nessus

## ⚠️ Warning
This guide is intended for educational and research purposes only. The use of tools and techniques described in this guide must comply with law and professional ethics. The responsibility for using the tools and techniques described in this guide lies solely with the user.

---
*Last updated: 2024*

### Nmap - Website-Specific Flags
```bash
# HTTP/HTTPS scanning
nmap -p80,443,8080,8443 -sV --script http-* target.com

# SSL/TLS testing
nmap -p443 --script ssl-* target.com

# Header testing
nmap --script http-headers target.com

# CORS testing
nmap --script http-cors target.com

# WAF detection
nmap --script http-waf-detect target.com

# robots.txt testing
nmap --script http-robots.txt target.com

# Server testing
nmap --script http-server-header target.com

# Directory testing
nmap --script http-enum target.com

# Detailed SSL/TLS testing
nmap -p443 --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed target.com

# HTTP Methods testing
nmap --script http-methods target.com

# HTTP Auth testing
nmap --script http-auth target.com

# HTTP Title testing
nmap --script http-title target.com
```

### Shodan - IP and Website Search
```bash
# Install Shodan CLI
pip install shodan

# Set API Key
shodan init YOUR_API_KEY

# Search by domain
shodan domain target.com

# Search by IP
shodan host IP_ADDRESS

# Search by technology
shodan search "http.title:'target.com'"

# Search by service
shodan search "ssl:target.com"

# Search by port
shodan search "port:443 ssl:target.com"

# Search by operating system
shodan search "os:'Windows' hostname:target.com"

# Search by server
shodan search "server:'nginx' hostname:target.com"

# Search by server version
shodan search "server:'nginx 1.18.0' hostname:target.com"

# Search by SSL/TLS
shodan search "ssl.cert.subject.CN:target.com"

# Search by ASN
shodan search "asn:AS12345"

# Search by geographic location
shodan search "country:US hostname:target.com"

# Search by organization
shodan search "org:'Target Organization'"

# Save results to file
shodan search "hostname:target.com" --fields ip_str,port,hostnames,org > results.txt

# Advanced search with filters
shodan search "hostname:target.com port:443,80,8080,8443 ssl:true"
```