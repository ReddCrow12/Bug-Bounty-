# Tomcat RCE Checker

A Python security testing tool for identifying Remote Code Execution (RCE) vulnerabilities in Apache Tomcat servers.

## ⚠️ Security Disclaimer

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

- Only use on systems you own or have explicit written permission to test
- Unauthorized use may violate laws and regulations
- Always follow responsible disclosure practices
- The authors are not responsible for misuse of this tool

## Features

- **Version Detection** - Identifies Apache Tomcat versions
- **Manager Application Discovery** - Locates administrative interfaces
- **Ghostcat Vulnerability Check** - Tests for CVE-2020-1938
- **WAR Upload Endpoint Detection** - Finds potential file upload vulnerabilities
- **Default Credentials Testing** - Checks common username/password combinations
- **Multi-threaded Scanning** - Concurrent vulnerability checks for faster results
- **Colored Output** - Easy-to-read results with status indicators

## Requirements

- Python 3.6+
- Required packages:
  ```
  requests
  colorama
  urllib3
  ```

## Installation

1. Clone or download the script
2. Install dependencies:
   ```bash
   pip install requests colorama urllib3
   ```

## Usage

### Basic Usage
```bash
python3 tomcat_rce_checker.py -t http://target.com:8080
```

### Verbose Mode
```bash
python3 tomcat_rce_checker.py -t http://target.com:8080 -v
```

### Command Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `-t, --target` | Target URL (e.g., http://example.com:8080) | ✓ |
| `-v, --verbose` | Enable verbose output for detailed information | ✗ |

## Vulnerability Checks

### 1. Version Detection
- Identifies Apache Tomcat version from server responses
- Flags specific vulnerable versions (e.g., 10.1.28)
- Helps determine applicable CVEs

### 2. Manager Application Check
- Scans for `/manager/html` endpoint
- Identifies accessible administrative interfaces
- Detects authentication requirements

### 3. Ghostcat Vulnerability (CVE-2020-1938)
- Tests for the infamous AJP connector vulnerability
- Affects Tomcat versions 6.x, 7.x, 8.x, and 9.x
- Can lead to sensitive file disclosure and RCE

### 4. WAR Upload Endpoints
- Searches for file upload functionality:
  - `/manager/html/upload`
  - `/manager/deploy`
  - `/manager/upload`
- Identifies potential paths for malicious WAR deployment

### 5. Default Credentials Testing
Tests common username/password combinations:
- `tomcat:tomcat`
- `admin:admin`
- `admin:tomcat`
- `tomcat:admin`
- `role1:role1`
- `role:changethis`
- `tomcat:s3cret`
- `admin:password`

## Output Examples

### Successful Detection
```
[14:25:10] INFO: Starting vulnerability scan for http://target.com:8080
[14:25:11] SUCCESS: Found Apache Tomcat server
[14:25:11] WARNING: Target is running Apache Tomcat 10.1.28
[14:25:12] WARNING: Manager application found (requires authentication)
[14:25:13] SUCCESS: Found working credentials: tomcat:tomcat
[14:25:14] WARNING: Target might be vulnerable to one or more RCE vulnerabilities!
```

### No Vulnerabilities Found
```
[14:25:10] INFO: Starting vulnerability scan for http://target.com:8080
[14:25:11] SUCCESS: Found Apache Tomcat server
[14:25:12] INFO: No obvious vulnerabilities found
```

## Status Indicators

- 🔵 **INFO**: General information and scan progress
- 🟢 **SUCCESS**: Successful detection or authentication
- 🟡 **WARNING**: Potential vulnerability or security concern
- 🔴 **ERROR**: Connection issues or scan errors

## Common Vulnerabilities Detected

### CVE-2020-1938 "Ghostcat"
- **Severity**: Critical
- **Affected Versions**: Tomcat 6.x, 7.x, 8.x, 9.x
- **Impact**: File disclosure, potential RCE
- **Mitigation**: Upgrade to patched version or disable AJP connector

### Manager Application Access
- **Severity**: High
- **Impact**: Application deployment, server control
- **Mitigation**: Strong authentication, IP restrictions, disable if unused

### Default Credentials
- **Severity**: Critical
- **Impact**: Full administrative access
- **Mitigation**: Change default passwords immediately

## Penetration Testing Workflow

1. **Reconnaissance**:
   ```bash
   python3 tomcat_rce_checker.py -t http://target.com:8080 -v
   ```

2. **Analyze Results**:
   - Note detected versions and compare with CVE databases
   - Document accessible manager interfaces
   - Record any successful credential combinations

3. **Further Testing** (if authorized):
   - Manual verification of detected vulnerabilities
   - Attempt to upload test WAR files
   - Explore file disclosure via Ghostcat

4. **Documentation**:
   - Screenshot evidence of vulnerabilities
   - Document impact and exploitation steps
   - Prepare remediation recommendations

## Remediation Recommendations

### Immediate Actions
- **Change default credentials** on all Tomcat installations
- **Upgrade** to latest patched versions
- **Disable AJP connector** if not required
- **Restrict access** to manager applications by IP

### Security Hardening
- Implement **strong authentication** mechanisms
- Use **HTTPS** for all administrative interfaces
- Enable **audit logging** for administrative actions
- Regular **security updates** and patch management

### Network Security
- **Firewall rules** to restrict access to Tomcat ports
- **VPN access** for administrative functions
- **Network segmentation** for web servers

## Troubleshooting

### Common Issues

1. **Connection Timeouts**:
   ```
   [ERROR] Error checking version: Connection timeout
   ```
   - Check target URL and port
   - Verify network connectivity
   - Ensure Tomcat is running

2. **SSL Certificate Errors**:
   - Tool automatically ignores SSL warnings
   - Use HTTP instead of HTTPS if needed

3. **False Positives**:
   - Manual verification recommended
   - Some checks are heuristic-based

### Debug Tips
- Use `-v` flag for detailed error messages
- Test with known vulnerable instances first
- Verify target accessibility with curl/browser

## Legal and Ethical Guidelines

### Before Testing
- ✅ Obtain **written authorization**
- ✅ Define **scope and limitations**
- ✅ Document **testing methodology**
- ✅ Plan **responsible disclosure** process

### During Testing
- ⚠️ **Minimize impact** on production systems
- ⚠️ **Avoid destructive actions**
- ⚠️ **Respect rate limits**
- ⚠️ **Document all activities**

### After Testing
- 📋 **Report findings** to appropriate parties
- 🔒 **Secure test data** and credentials
- 🤝 **Assist with remediation** if requested
- ⏰ **Follow up** on fix implementation

## Contributing

Contributions are welcome! Please:
- Follow secure coding practices
- Add proper error handling
- Include documentation for new checks
- Test against various Tomcat versions

## Version History

- **v1.0**: Initial release with basic vulnerability checks
- Support for Tomcat versions 6.x - 10.x
- Multi-threaded scanning capabilities

## Resources

- [Apache Tomcat Security](https://tomcat.apache.org/security.html)
- [CVE-2020-1938 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## License

This tool is provided for educational and authorized security testing purposes only. Use in accordance with applicable laws and with proper authorization.