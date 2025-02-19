# SSH Monitor Script

This is a simple Bash script that monitors SSH logs from `journalctl` and sends Telegram alerts based on specified conditions. The script notifies you when:

- A successful SSH login occurs (both for "ubuntu" and other users).
- A failed SSH login attempt is detected.
- A login attempt is made with an invalid user.

In addition, the script automatically drops connections and blacklists IP addresses for failed or invalid login attempts using `iptables`.

## Prerequisites

- A Linux system using `systemd` (with access to `journalctl` logs).
- `curl` installed for making HTTP requests.
- `iptables` for managing firewall rules.
- Proper permissions (run as `root` or using `sudo`) to access logs and modify firewall rules.

## Configuration

Edit the script file (`ssh_monitor.sh`) and update the following variables:

- `BOT_TOKEN`: Your Telegram Bot token.
- `CHAT_ID`: Your Telegram chat ID.
- Optionally modify `BLACKLIST_FILE` if you’d like to use a different path for storing blacklisted IPs (default is `/var/log/ssh_blacklist`).

## Running the Script

Run the script manually from the terminal:

```bash
sudo ./ssh_monitor.sh
```

### Running in the Background

To run the script in the background, you can use `nohup`:

```bash
nohup sudo ./ssh_monitor.sh > ssh_monitor.log 2>&1 &
```

Alternatively, consider running it in a `screen` or `tmux` session.

### Using systemd Service

To run the script as a service, create a systemd service file, for example `/etc/systemd/system/ssh_monitor.service`:

```ini
[Unit]
Description=SSH Log Monitor Service
After=network.target

[Service]
ExecStart=/path/to/ssh_monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Replace `/path/to/ssh_monitor.sh` with the actual path of your script. Then reload the systemd daemon and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl start ssh_monitor.service
```