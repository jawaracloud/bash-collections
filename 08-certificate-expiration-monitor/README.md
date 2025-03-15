# Certificate Expiration Monitor

A Bash script that monitors SSL/TLS certificates across multiple domains and alerts you when they're approaching expiration.

## Features

- Check SSL certificates for multiple domains from a configuration file
- Configurable threshold for expiration warnings (default: 30 days)
- Multiple notification options (terminal, and Slack)
- Detailed reporting with certificate issuer information
- Error handling for connection and parsing issues
- Easy to set up as a cron job for automated monitoring

## Requirements

- Bash shell
- OpenSSL
- curl (for Slack notifications)

## Installation

1. Download the script:
   ```bash
   curl -o cert_monitor.sh https://raw.githubusercontent.com/jawaracloud/bash-collections/main/08-certificate-expiration-monitor/cert_monitor.sh
   ```

2. Make it executable:
   ```bash
   chmod +x cert_monitor.sh
   ```

3. Create a domains file with one domain per line:
   ```bash
   echo "example.com" > domains.txt
   echo "github.com" >> domains.txt
   ```

## Usage

### Basic usage:

```bash
./cert_monitor.sh -f domains.txt
```

### With notification options:

```bash
./cert_monitor.sh -f domains.txt -d 14 -e admin@example.com -s https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Options:

- `-f, --file FILE`: Path to domains file (one domain per line)
- `-d, --days NUMBER`: Alert threshold in days (default: 30)
- `-s, --slack WEBHOOK`: Slack webhook URL for notifications
- `-q, --quiet`: Suppress terminal output
- `-h, --help`: Display help message

## Setting up as a Cron Job

To run the script automatically, add it to your crontab:

```bash
# Edit crontab
crontab -e

# Add a line to run the script daily at 8 AM
0 8 * * * /path/to/cert_monitor.sh -f /path/to/domains.txt -e admin@example.com -q
```

## Example Output

```
SSL Certificate Expiration Report
Generated on: Mon Mar 16 2025
Alert threshold: 30 days
------------------------------------------------
example.com: WARNING! Certificate expires in 25 days
  Issuer: CN=R3,O=Let's Encrypt,C=US
  Expiry date: Apr 10 12:00:00 2025 GMT

github.com: Connection error
------------------------------------------------
Summary: 1 certificates expiring soon, 1 errors
```

## Integration with Other Scripts

This script can be integrated with your existing subdomain finder script (02-find-subdomains) to automatically monitor certificates for all discovered subdomains:

```bash
# Find subdomains and save to a file
./02-find-subdomains/crt.sh example.com > domains.txt

# Check certificates for all discovered subdomains
./cert_monitor.sh -f domains.txt
```