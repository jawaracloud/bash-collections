#!/bin/bash
# SSH Monitor Script: Monitor SSH logs, send Telegram alerts, and blacklist IPs.
#
# Requirements:
#   - curl must be installed.
#   - Run this script with proper permissions to read journalctl logs and modify iptables.
#
# Configure your Telegram Bot settings below:
BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
CHAT_ID="YOUR_TELEGRAM_CHAT_ID"

# File to keep track of blacklisted IPs.
BLACKLIST_FILE="/var/log/ssh_blacklist"

# Ensure the blacklist file exists.
if [ ! -f "$BLACKLIST_FILE" ]; then
  touch "$BLACKLIST_FILE"
fi

# Function to send a Telegram message via Bot API with Markdown formatting.
send_telegram_message() {
  local message="$1"
  curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
       -d chat_id="${CHAT_ID}" \
       -d parse_mode="Markdown" \
       -d text="$message" > /dev/null
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
  send_telegram_message "*🔒 Blacklisted IP:*\n\`$ip\` has been dropped from further connections."
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

_Log:_
\`$line\`
EOF
)
      send_telegram_message "$msg"
    else
      msg=$(cat <<EOF
*✅ SSH SUCCESS (ubuntu)*
User: \`$user\`
logged in.

_Log:_
\`$line\`
EOF
)
      send_telegram_message "$msg"
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

_Log:_
\`$line\`
EOF
)
    send_telegram_message "$msg"
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

_Log:_
\`$line\`
EOF
)
      send_telegram_message "$msg"
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
