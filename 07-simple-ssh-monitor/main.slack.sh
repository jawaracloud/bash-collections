#!/bin/bash
# SSH Monitor Script: Monitor SSH logs, send Slack alerts, and blacklist IPs.
#
# Requirements:
#   - curl must be installed.
#   - Run this script with proper permissions to read journalctl logs and modify iptables.
#
# Configure your Slack Webhook settings below:
SLACK_WEBHOOK_URL="YOUR_SLACK_WEBHOOK_URL"

# File to keep track of blacklisted IPs.
BLACKLIST_FILE="/var/log/ssh_blacklist"

# Ensure the blacklist file exists.
if [ ! -f "$BLACKLIST_FILE" ]; then
  touch "$BLACKLIST_FILE"
fi

# Function to send a Slack message via Webhook
send_slack_message() {
  local message="$1"
  local color="$2"  # Can be 'good' (green), 'warning' (yellow), 'danger' (red), or any hex color

  # Format JSON payload for Slack
  local payload=$(cat <<EOF
{
  "attachments": [
    {
      "color": "$color",
      "text": "$message",
      "mrkdwn_in": ["text"]
    }
  ]
}
EOF
)

  # Send the message to Slack
  curl -s -X POST -H "Content-type: application/json" \
       --data "$payload" \
       $SLACK_WEBHOOK_URL > /dev/null
}

# Function to drop connection and blacklist the IP address.
drop_and_blacklist() {
  local ip="$1"
  # Check if the IP is already blacklisted.
  if grep -q "$ip" "$BLACKLIST_FILE" 2>/dev/null; then
    return
  fi
  # Drop the connection using iptables.
  iptables -I INPUT -s "$ip" -j DROP
  # Log the blacklisted IP.
  echo "$ip" >> "$BLACKLIST_FILE"
  send_slack_message "*🔒 Blacklisted IP:*\n\`$ip\` has been dropped from further connections." "danger"
}

# Function to extract the IP address from a log line.
extract_ip() {
  local line="$1"
  # Attempt to extract an IPv4 address after the "from" keyword.
  ip=$(echo "$line" | awk '{for(i=1;i<=NF;i++){ if($i=="from"){print $(i+1); exit} }}')
  # Fallback to basic regex if not found.
  if [ -z "$ip" ]; then
    ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
  fi
  echo "$ip"
}

# Function to process each log line.
process_line() {
  local line="$1"
  # Check for successful login (e.g., "Accepted password for ..." or "Accepted publickey for ...").
  if echo "$line" | grep -qE "Accepted (password|publickey) for"; then
    # Extract the username: assume the token right after "for" is the username.
    user=$(echo "$line" | awk '/Accepted/ {for(i=1;i<=NF;i++){ if($i=="for"){print $(i+1); exit}}}')
    
    if [[ "$user" != "ubuntu" ]]; then
      msg=$(cat <<EOF
*✅ SSH SUCCESS*
User: \`$user\`
has successfully logged in.
*Log:*
\`$line\`
EOF
)
      send_slack_message "$msg" "good"
    else
      msg=$(cat <<EOF
*✅ SSH SUCCESS (ubuntu)*
User: \`$user\`
logged in.
*Log:*
\`$line\`
EOF
)
      send_slack_message "$msg" "good"
    fi
    return
  fi

  # Check for failed login containing "Failed password".
  if echo "$line" | grep -q "Failed password"; then
    if echo "$line" | grep -qi "invalid user"; then
      user=$(echo "$line" | awk '/invalid user/ {for(i=1;i<=NF;i++){ if($i=="user"){print $(i+1); exit}}}')
    else
      user=$(echo "$line" | awk '/Failed password/ {for(i=1;i<=NF;i++){ if($i=="for"){print $(i+1); exit}}}')
    fi
    msg=$(cat <<EOF
*❌ SSH FAILURE*
Login failed for user: \`$user\`.
*Log:*
\`$line\`
EOF
)
    send_slack_message "$msg" "danger"
    ip=$(extract_ip "$line")
    if [ -n "$ip" ]; then
      drop_and_blacklist "$ip"
    fi
    return
  fi

  # Check for attempts with invalid user messages.
  if echo "$line" | grep -qi "invalid user"; then
    user=$(echo "$line" | awk '/invalid user/ {for(i=1;i<=NF;i++){ if($i=="user"){print $(i+1); exit}}}')
    if [[ "$user" != "ubuntu" ]]; then
      msg=$(cat <<EOF
*⚠️ SSH ATTEMPT*
Invalid login attempt for user: \`$user\`.
*Log:*
\`$line\`
EOF
)
      send_slack_message "$msg" "warning"
      ip=$(extract_ip "$line")
      if [ -n "$ip" ]; then
        drop_and_blacklist "$ip"
      fi
    fi
    return
  fi
}

# Main: Follow logs for ssh.service & ssh.socket via journalctl.
echo "Starting SSH monitoring..."
journalctl -u ssh.service -u ssh.socket -f -n 0 | while IFS= read -r logline
do
  process_line "$logline"
done
