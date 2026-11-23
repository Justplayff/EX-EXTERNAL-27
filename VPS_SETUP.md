# VPS Setup Guide for ZEX Injection

## Prerequisites
- VPS with Ubuntu/Debian Linux
- Root access (SSH: `ssh root@138.249.138.78`)
- Python 3.8+ installed

## Step 1: Connect to Your VPS

```bash
ssh root@138.249.138.78
```

## Step 2: Update System and Install Dependencies

```bash
# Update package list
apt update && apt upgrade -y

# Install Python 3 and pip
apt install python3 python3-pip -y

# Install required Python packages
pip3 install flask python-dotenv python-telegram-bot
```

## Step 3: Create Application Directory

```bash
# Create app directory
mkdir -p /root/zex-injector
cd /root/zex-injector

# Create required directories
mkdir -p slot_files/option1
mkdir -p slot_files/option2
mkdir -p slot_files/option3
mkdir -p slot_files/option4
mkdir -p slot_files/option5
```

## Step 4: Upload Server Files

Upload these files from your local machine to the VPS:
- `server.py` (or `vps_server.py`)
- `.env` (create from template below)
- `config.json` (or use the generated default)
- `keys.json` (or use the generated default)

Using SCP from your local machine:
```bash
scp server.py root@138.249.138.78:/root/zex-injector/
scp .env root@138.249.138.78:/root/zex-injector/
scp vps_config_latest.json root@138.249.138.78:/root/zex-injector/config.json
```

## Step 5: Configure Firewall

```bash
# Allow port 9009 (or your chosen port)
ufw allow 9009/tcp

# Enable firewall if not already enabled
ufw enable
```

## Step 6: Create Systemd Service (Auto-start on boot)

```bash
# Create service file
nano /etc/systemd/system/zex-injector.service
```

Paste this content:
```ini
[Unit]
Description=ZEX Injection VPS Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/zex-injector
ExecStart=/usr/bin/python3 /root/zex-injector/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Save and exit (Ctrl+X, Y, Enter).

```bash
# Enable and start service
systemctl daemon-reload
systemctl enable zex-injector
systemctl start zex-injector

# Check status
systemctl status zex-injector
```

## Step 7: Verify Server is Running

```bash
# Check if port is listening
netstat -tlnp | grep 9009

# Test the API
curl http://localhost:9009/config
curl http://localhost:9009/health
```

## Step 8: Upload Initial Config

From your local machine, upload the updated config:
```bash
scp vps_config_latest.json root@138.249.138.78:/root/zex-injector/config.json
```

Then restart the service:
```bash
ssh root@138.249.138.78 "systemctl restart zex-injector"
```

## Step 9: Upload Slot Files (Optional)

Upload your mod files to the VPS:
```bash
# Example: upload a file to option1 slot 4
scp your_file.bin root@138.249.138.78:/root/zex-injector/slot_files/option1/4/
```

## Step 10: Test from iOS App

1. Rebuild your iOS app with the updated `ZXSecurity.h`
2. Install on device
3. The app should now connect to `http://138.249.138.78:9009`

## Useful Commands

```bash
# View logs
journalctl -u zex-injector -f

# Restart service
systemctl restart zex-injector

# Stop service
systemctl stop zex-injector

# View config
cat /root/zex-injector/config.json

# Edit config
nano /root/zex-injector/config.json
```

## Troubleshooting

### Port already in use
```bash
# Find process using port 9009
lsof -i :9009
# Kill it if needed
kill -9 <PID>
```

### Python not found
```bash
# Check Python version
python3 --version
# Install if missing
apt install python3 -y
```

### Firewall blocking
```bash
# Check firewall status
ufw status
# Allow port
ufw allow 9009/tcp
```

## Security Notes

1. Change the default port from 9009 to something else for better security
2. Use strong SSH keys instead of password authentication
3. Keep your Telegram bot token secure
4. Regularly update your VPS: `apt update && apt upgrade`
