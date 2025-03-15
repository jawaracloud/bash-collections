#!/bin/bash
#
# cert_monitor.sh - SSL Certificate Expiration Monitor
#
# This script checks SSL certificates for multiple domains and alerts when
# certificates are approaching expiration. It can be run as a cron job to
# provide regular monitoring.
#
# Usage: ./cert_monitor.sh [options]
#
# Options:
#   -f, --file FILE       Path to domains file (one domain per line)
#   -d, --days NUMBER     Alert threshold in days (default: 30)
#   -s, --slack WEBHOOK   Slack webhook URL for notifications
#   -q, --quiet           Suppress terminal output
#   -h, --help            Display this help message
#
# Example:
#   ./cert_monitor.sh -f domains.txt -d 30 -e admin@example.com

set -e

# Default values
DOMAINS_FILE=""
THRESHOLD_DAYS=30
SLACK_WEBHOOK=""
QUIET=false
CURRENT_DATE=$(date +%s)
TEMP_FILE=$(mktemp)
OUTPUT_FILE=$(mktemp)

# Trap for cleanup
trap 'rm -f "$TEMP_FILE" "$OUTPUT_FILE"' EXIT

# Text formatting
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Function to display help
show_help() {
    grep '^#' "$0" | grep -v '#!/bin/bash' | sed 's/^# \?//'
    exit 0
}

# Function to check arguments
check_args() {
    if [ -z "$DOMAINS_FILE" ]; then
        echo -e "${RED}Error: Domains file is required${NC}"
        show_help
    fi
    
    if [ ! -f "$DOMAINS_FILE" ]; then
        echo -e "${RED}Error: Domains file '$DOMAINS_FILE' not found${NC}"
        exit 1
    fi
}

# Function to send slack notification
send_slack() {
    if [ -n "$SLACK_WEBHOOK" ]; then
        CONTENT=$(cat "$OUTPUT_FILE" | sed 's/$/\\n/g' | tr -d '\n')
        curl -s -X POST -H 'Content-type: application/json' --data "{\"text\":\"SSL Certificate Expiration Alert:\\n$CONTENT\"}" "$SLACK_WEBHOOK"
        [ "$QUIET" = false ] && echo -e "${GREEN}Slack notification sent${NC}"
    fi
}

# Parse command line arguments
while [ "$#" -gt 0 ]; do
    case "$1" in
        -f|--file)
            DOMAINS_FILE="$2"
            shift 2
            ;;
        -d|--days)
            THRESHOLD_DAYS="$2"
            shift 2
            ;;
        -s|--slack)
            SLACK_WEBHOOK="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            ;;
    esac
done

check_args

# Header for output
echo "SSL Certificate Expiration Report" > "$OUTPUT_FILE"
echo "Generated on: $(date)" >> "$OUTPUT_FILE"
echo "Alert threshold: $THRESHOLD_DAYS days" >> "$OUTPUT_FILE"
echo "------------------------------------------------" >> "$OUTPUT_FILE"

# Counter for certificates with issues
EXPIRING_COUNT=0
ERROR_COUNT=0

# Check each domain
[ "$QUIET" = false ] && echo -e "${BOLD}Checking SSL certificates...${NC}"

while read -r domain; do
    # Skip empty lines and comments
    [[ -z "$domain" || "$domain" =~ ^# ]] && continue
    
    domain=$(echo "$domain" | tr -d '[:space:]')
    [ "$QUIET" = false ] && echo -n "Checking $domain... "
    
    # Get certificate info
    if ! timeout 10 echo | openssl s_client -servername "$domain" -connect "$domain":443 2>/dev/null > "$TEMP_FILE"; then
        [ "$QUIET" = false ] && echo -e "${RED}ERROR: Could not connect${NC}"
        echo "$domain: Connection error" >> "$OUTPUT_FILE"
        ((ERROR_COUNT++))
        continue
    fi
    
    # Extract expiration date
    if ! EXPIRY_DATE=$(openssl x509 -noout -enddate -in "$TEMP_FILE" 2>/dev/null | sed -n 's/notAfter=//p'); then
        [ "$QUIET" = false ] && echo -e "${RED}ERROR: Could not parse certificate${NC}"
        echo "$domain: Certificate parsing error" >> "$OUTPUT_FILE"
        ((ERROR_COUNT++))
        continue
    fi
    
    # Convert to timestamp
    EXPIRY_TIMESTAMP=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null)
    if [ $? -ne 0 ]; then
        [ "$QUIET" = false ] && echo -e "${RED}ERROR: Invalid date format${NC}"
        echo "$domain: Date parsing error" >> "$OUTPUT_FILE"
        ((ERROR_COUNT++))
        continue
    fi
    
    # Calculate days until expiry
    DAYS_LEFT=$(( ($EXPIRY_TIMESTAMP - $CURRENT_DATE) / 86400 ))
    
    # Get issuer information
    ISSUER=$(openssl x509 -noout -issuer -in "$TEMP_FILE" | sed -n 's/issuer=//p')
    
    # Check if certificate is expiring soon
    if [ "$DAYS_LEFT" -lt "$THRESHOLD_DAYS" ]; then
        if [ "$DAYS_LEFT" -lt 0 ]; then
            [ "$QUIET" = false ] && echo -e "${RED}EXPIRED ($DAYS_LEFT days)${NC}"
            echo "$domain: EXPIRED! Certificate expired $((DAYS_LEFT * -1)) days ago" >> "$OUTPUT_FILE"
        else
            [ "$QUIET" = false ] && echo -e "${YELLOW}WARNING ($DAYS_LEFT days)${NC}"
            echo "$domain: WARNING! Certificate expires in $DAYS_LEFT days" >> "$OUTPUT_FILE"
        fi
        echo "  Issuer: $ISSUER" >> "$OUTPUT_FILE"
        echo "  Expiry date: $EXPIRY_DATE" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        ((EXPIRING_COUNT++))
    else
        [ "$QUIET" = false ] && echo -e "${GREEN}OK ($DAYS_LEFT days)${NC}"
    fi
    
done < "$DOMAINS_FILE"

# Footer for output
echo "------------------------------------------------" >> "$OUTPUT_FILE"
echo "Summary: $EXPIRING_COUNT certificates expiring soon, $ERROR_COUNT errors" >> "$OUTPUT_FILE"

# Send notifications if needed
if [ "$EXPIRING_COUNT" -gt 0 ] || [ "$ERROR_COUNT" -gt 0 ]; then
    send_slack
fi

# Display summary
if [ "$QUIET" = false ]; then
    echo -e "\n${BOLD}Summary:${NC}"
    echo -e "$EXPIRING_COUNT certificates expiring within $THRESHOLD_DAYS days"
    echo -e "$ERROR_COUNT errors encountered"
    
    # Show report if there are issues
    if [ "$EXPIRING_COUNT" -gt 0 ] || [ "$ERROR_COUNT" -gt 0 ]; then
        echo -e "\n${BOLD}Report:${NC}"
        cat "$OUTPUT_FILE"
    fi
fi

exit 0