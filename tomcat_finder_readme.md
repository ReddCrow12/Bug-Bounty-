# Tomcat Finder

A Python tool for discovering Apache Tomcat servers across multiple domains and checking for potential security vulnerabilities.

## Features

- **Multi-threaded scanning** for faster domain processing
- **Version detection** of Apache Tomcat servers
- **Common path enumeration** (manager, docs, examples, etc.)
- **AJP port scanning** (port 8009) for potential security issues
- **Detailed reporting** with colored output
- **Export results** to file for further analysis

## Requirements

- Python 3.6+
- Required packages:
  ```
  requests
  beautifulsoup4
  colorama
  urllib3
  ```

## Installation

1. Clone or download the script
2. Install dependencies:
   ```bash
   pip install requests beautifulsoup4 colorama urllib3
   ```

## Usage

### Basic Usage
```bash
python3 tomcat_finder.py -i domains.txt
```

### Advanced Usage
```bash
python3 tomcat_finder.py -i domains.txt -o results.txt -t 20 -v
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --input` | Input file containing domains (one per line) | **Required** |
| `-o, --output` | Output file for results | Optional |
| `-t, --threads` | Number of concurrent threads | 10 |
| `-v, --verbose` | Enable verbose output | Disabled |

## Input Format

Create a text file with one domain per line:
```
example.com
test.example.org
192.168.1.100:8080
subdomain.example.net
```

The tool automatically handles:
- Domains with or without `http://` prefix
- Custom ports (e.g., `domain.com:8080`)
- IP addresses

## What It Checks

### Common Tomcat Paths
- `/` (root)
- `/manager/html` (Tomcat Manager)
- `/host-manager/html` (Host Manager)
- `/docs/` (Documentation)
- `/examples/` (Example applications)
- `/ROOT/` (Root application)
- `/tomcat/`
- `/tomcat-docs/`

### Security Checks
- **AJP Connector** (port 8009) - Checks if the Apache JServ Protocol port is open
- **Version Detection** - Identifies Tomcat version for vulnerability assessment
- **Manager Interface** - Detects accessible management interfaces

## Output

### Console Output
The tool provides colored, timestamped output:
- 🔵 **INFO**: General information and progress
- 🟢 **SUCCESS**: Tomcat servers found with secure configuration
- 🟡 **WARNING**: Tomcat servers with potential security issues (open AJP port)
- 🔴 **ERROR**: Connection or processing errors

### Example Output
```
[10:30:15] INFO: Starting scan with 10 threads
[10:30:16] SUCCESS: Found Tomcat 9.0.1 at example.com/ (AJP: Closed)
[10:30:17] WARNING: Found Tomcat 8.5.23 at test.com/manager/html (AJP: Open)
[10:30:18] INFO: Title: Apache Tomcat/8.5.23

Scan Summary:
[10:30:20] INFO: Total domains checked: 100
[10:30:20] INFO: Found Tomcat servers: 3

Vulnerable servers (AJP port open):
[10:30:20] WARNING: Domain: test.com
Version: 8.5.23
Path: /manager/html
Title: Apache Tomcat/8.5.23
```

## Security Implications

### AJP Connector (Port 8009)
- **Open AJP ports** may indicate potential security vulnerabilities
- Can be exploited for **file inclusion attacks** (CVE-2020-1938 "Ghostcat")
- Should typically be **firewalled** or **disabled** if not needed

### Manager Interfaces
- Accessible `/manager/html` endpoints may allow **application deployment**
- Should be **properly secured** with strong authentication
- Consider **IP restrictions** for administrative interfaces

## Example Workflow

1. **Prepare domain list**:
   ```bash
   echo "example.com" > domains.txt
   echo "test.example.org" >> domains.txt
   echo "192.168.1.100:8080" >> domains.txt
   ```

2. **Run the scan**:
   ```bash
   python3 tomcat_finder.py -i domains.txt -o results.txt -v
   ```

3. **Review results**:
   - Check console output for immediate findings
   - Review `results.txt` for detailed analysis
   - Prioritize servers with open AJP ports

## Performance Tuning

- **Threads**: Increase `-t` value for faster scanning (default: 10)
- **Timeout**: Modify `timeout` parameter in code for slower networks
- **Large lists**: Process domains in batches for very large input files

## Troubleshooting

### Common Issues

1. **SSL Certificate Errors**: 
   - The tool automatically ignores SSL certificate warnings
   
2. **Connection Timeouts**:
   - Increase timeout value in the code
   - Reduce thread count for unstable networks

3. **Permission Errors**:
   - Ensure read access to input file
   - Check write permissions for output file

### Error Messages
- `Error checking domain`: Network connectivity issues
- `Could not get title`: HTTP response parsing problems
- `Scan interrupted by user`: Ctrl+C pressed during execution

## Legal and Ethical Considerations

⚠️ **Important**: This tool is for **authorized security testing only**

- Only scan domains you **own** or have **explicit permission** to test
- Respect **rate limits** and **terms of service**
- Follow **responsible disclosure** practices for any vulnerabilities found
- Consider the **impact** on target systems when choosing thread counts

## Contributing

Feel free to submit issues and enhancement requests. When contributing:
- Follow Python coding standards
- Add appropriate error handling
- Include documentation for new features
- Test with various Tomcat versions

## License

This tool is provided for educational and authorized security testing purposes only. Use responsibly and in accordance with applicable laws and regulations.