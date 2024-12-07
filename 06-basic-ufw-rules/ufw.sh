#!/bin/bash

# UFW Firewall Configuration Script
# Enhanced security and logging configuration

# Ensure script is run with sudo privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with sudo" 
   exit 1
fi

# Reset UFW to ensure a clean configuration
sudo ufw reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH - Use non-standard port for added security
# Assumes you've changed SSH port to 22222 in /etc/ssh/sshd_config
sudo ufw allow 22222/tcp comment "SSH Custom Port"

# Web server ports
sudo ufw allow 80/tcp comment "HTTP"
sudo ufw allow 443/tcp comment "HTTPS"

# Optional: Limit SSH connections to prevent brute force
sudo ufw limit 22222/tcp comment "Limit SSH connections"

# Optional: Allow specific services or applications
# Uncomment and modify as needed
# sudo ufw allow from 192.168.1.0/24 to any port 5432 comment "PostgreSQL from local network"
# sudo ufw allow from 10.0.0.0/8 comment "Allow all from internal network"

# Logging
sudo ufw logging on
sudo ufw logging high

# Enable firewall
sudo ufw enable

# Verify firewall status and open ports
echo "Firewall Status:"
sudo ufw status verbose

# List all active network connections and listening ports
echo -e "\nActive Network Connections:"
sudo netstat -tulpn

# Optional: Additional security check
echo -e "\nOpen Ports and Listening Services:"
ss -tulpn

# Optionally, you can add a function to check for potential vulnerabilities
check_open_ports() {
    echo "Checking for potentially unnecessary open ports:"
    netstat -tuln | grep -E '0.0.0.0:\*|:::*' | while read proto recv send local foreign state prog; do
        port=$(echo $local | cut -d: -f2)
        if [[ ! " 22222 80 443 " =~ " $port " ]]; then
            echo "Warning: Unexpected open port $port"
        fi
    done
}

# Uncomment to run the port check
# check_open_ports

exit 0
