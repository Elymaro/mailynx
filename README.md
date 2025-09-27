# Mailynx

## Description
Mailynx.sh is a Bash script designed to automate email security configurations and checks. It supports SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting & Conformance) configurations. Additionally, it can perform batch processing and generate reports in HTML or Markdown formats.

## Installation
To use Mailynx.sh, follow these steps:

1. Clone the repository or download the script.
2. Make the script executable:
   ```bash
   chmod +x mailynx.sh
   ```
## Usage
   ```bash
   ./mailynx.sh -d example.com -o example.md
   ```
   ```bash
   ./mailynx.sh -L domains-list -o domains-list.html -H 
   ```
## Disclaimer
This tool is designed for educational and security purposes only. Use it responsibly and only on systems you have permission to test. Misuse of this tool can lead to legal consequences. Always ensure you have proper authorization before performing any security tests.

## Acknowledgements
Special thanks to Elymaro for the original project which this script is forked from.


