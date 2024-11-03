<div align="center">

# <span style="color: #007ACC;">SSH ALERT SERVICE</span>

<img src="./web/banner.webp" alt="SSH_ALERT Logo" width="700">

<p align="center">
  <img src="https://img.shields.io/badge/Author-rubikproxy-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Open%20Source-Yes-darkgreen?style=flat-square">
  <img src="https://img.shields.io/badge/Maintained%3F-Yes-lightblue?style=flat-square">
  <img src="https://img.shields.io/badge/Written%20In-python-darkcyan?style=flat-square">
</p>

</div>

---

## <span style="color: #007ACC;">Overview</span>

`SSH_ALERT` is a Python-based monitoring tool that sends real-time notifications for SSH login attempts (successful and failed) via Telegram. It monitors SSH authentication logs to provide instant alerts, enhancing server security by keeping you informed of access activities.

---

## <span style="color: #007ACC;">Installation and Setup</span>

### <span style="color: #007ACC;">Prerequisites</span>

Ensure the following software is installed:

- **Python 3**: Install using:
  ```bash
  sudo apt install python3
  ```
- **pip**: Install using:
  ```bash
  sudo apt install python3-pip
  ```
- **rsyslog**: Used for logging SSH authentication attempts.

---

### <span style="color: #007ACC;">Install and Configure Rsyslog</span>

1. **Install Rsyslog**:
   ```bash
   sudo apt install rsyslog
   ```

2. **Verify Rsyslog**:
   ```bash
   rsyslogd -v
   ```

3. **Enable Authentication Logging**:
   - Edit Rsyslog configuration:
     ```bash
     sudo nano /etc/rsyslog.conf
     ```
   - Ensure this line is uncommented:
     ```bash
     auth,authpriv.*    /var/log/auth.log
     ```

4. **Restart Rsyslog**:
   ```bash
   sudo systemctl restart rsyslog
   ```

---

### <span style="color: #007ACC;">Configure SSH_ALERT</span>

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/rubikproxy/SSHALERT.git
   ```

2. **Navigate to SSH_ALERT Directory**:
   ```bash
   cd /SSHALERT/
   ```

3. **Set Up the Systemd Service**:
   ```bash
   sudo ln -s /SSHALERT/sshalert.service /etc/systemd/system/sshalert.service
   ```

4. **Link Init Script and Make Executable**:
   ```bash
   sudo ln -s /SSHALERT/sshalert /etc/init.d/sshalert
   sudo chmod +x /etc/init.d/sshalert
   ```

### <span style="color: #007ACC;">Verify Installation</span>

To confirm that `sshalert` is running, check the process:
```bash
ps aux | grep sshalert
```

---

## <span style="color: #007ACC;">Configuration</span>

1. **Edit Configuration File**:
   - Open `./config.json` and set up Telegram bot token and chat ID:
   ```json
   {
     "telegram": {
       "bot_token": "YOUR_BOT_TOKEN",
       "chat_id": "YOUR_CHAT_ID"
     },
     "log": {
       "file_path": "/var/log/auth.log"
     }
   }
   ```

2. **Service Management**:
   - **Start the Service**:
     ```bash
     sudo systemctl start sshalert
     ```
   - **Enable on Boot**:
     ```bash
     sudo systemctl enable sshalert
     ```
   - **Check Service Status**:
     ```bash
     sudo systemctl status sshalert
     ```

---

## <span style="color: #007ACC;">Usage</span>

`SSH_ALERT` automatically monitors `/var/log/auth.log` for SSH login attempts and failed logins, sending real-time notifications to your configured Telegram chat.

### <span style="color: #007ACC;">Logging</span>

All alerts are logged to `/var/log/SSH-Alert/sshalert.log` within the SSH_ALERT directory for easy tracking and analysis.

---

## <span style="color: #007ACC;">Troubleshooting</span>

- **Log Checking**: If alerts aren't sent, check `tail -f /var/log/SSH-Alert/sshalert.log` for errors.
- **Permission Issues**: Run the script with root permissions.
- **Firewall**: Ensure your firewall allows outgoing connections to Telegram.

---

## <span style="color: #007ACC;">Conclusion</span>

`SSH_ALERT` is a powerful, simple-to-use tool to monitor SSH access and keep your server secure. Regularly check logs and update bot credentials as needed to ensure continuous operation.