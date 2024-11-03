# SSH Alert Monitoring Service - Developer Documentation

## Overview

The **SSH Alert Monitoring Service** monitors SSH login attempts on a server, sending email and SMS alerts for both successful and failed login attempts. The script leverages **Twilio** for SMS notifications and **SMTP** for email notifications, making it ideal for security monitoring on servers where tracking login activity is critical.

## Table of Contents
1. [Setup and Configuration](#setup-and-configuration)
2. [Service Control](#service-control)
3. [Configuration Parameters](#configuration-parameters)
4. [Functionality Overview](#functionality-overview)
5. [Error Handling and Troubleshooting](#error-handling-and-troubleshooting)
6. [Dependencies](#dependencies)

## 1. Setup and Configuration

### Prerequisites
1. **Python 3.x**: Ensure Python 3 is installed on your server.
2. **Required Python Packages**: Install packages using `pip install -r requirements.txt` where `requirements.txt` includes:
   - `smtplib` (built-in for email)
   - `twilio` (for SMS)
   - `datetime`, `time`, `json`, `signal`, and `sys` (all built-in)

### Service Setup
1. **Clone or Copy the Script**: Copy the main `ssh_alert_monitor.py` script to the server.
2. **Create `config.json`**: Add a `config.json` file to the same directory with the following structure:

   ```json
   {
     "email": {
       "address": "your-email@gmail.com",
       "password": "your-email-password",
       "to": "recipient-email@example.com"
     },
     "twilio": {
       "account_sid": "your-twilio-account-sid",
       "auth_token": "your-twilio-auth-token",
       "phone_number": "your-twilio-phone-number",
       "to_phone_number": "recipient-phone-number"
     },
     "log": {
       "file_path": "/var/log/auth.log"  // Adjust path to your system's auth log
     }
   }
   ```

3. **Configure as a Systemd Service**:
   - Create a service file: `/etc/systemd/system/sshalert.service`
   - Add the following configuration:

     ```ini
     [Unit]
     Description=SSH Alert Monitoring Service

     [Service]
     ExecStart=/usr/bin/python3 /path/to/ssh_alert_monitor.py
     WorkingDirectory=/path/to/
     StandardOutput=journal
     StandardError=journal
     Restart=on-failure

     [Install]
     WantedBy=multi-user.target
     ```

4. **Enable and Start the Service**:
   ```bash
   sudo systemctl enable sshalert
   sudo systemctl start sshalert
   sudo service sshalert start
   ```

## 2. Service Control

Control the service with these commands:
- **Start Service**: `sudo systemctl start sshalert` or `sudo service sshalert start`
- **Stop Service**: `sudo systemctl stop sshalert` or `sudo service sshalert stop`
- **Restart Service**: `sudo systemctl restart sshalert` or ``sudo service  sshalert restart``
- **Check Status**: `sudo systemctl status sshalert` or ``sudo service sshalert status``

## 3. Configuration Parameters

The `config.json` contains configurable parameters:

| Parameter                | Description |
|--------------------------|-------------|
| **email.address**        | Sender email address used for SMTP. |
| **email.password**       | Password for the sender email. |
| **email.to**             | Recipient email address. |
| **twilio.account_sid**   | Twilio Account SID for SMS alerts. |
| **twilio.auth_token**    | Twilio Auth Token for SMS alerts. |
| **twilio.phone_number**  | Twilio phone number for sending SMS. |
| **twilio.to_phone_number** | Recipient's phone number for SMS. |
| **log.file_path**        | Path to the SSH authentication log (e.g., `/var/log/auth.log`). |

## 4. Functionality Overview

The main script includes functions to monitor SSH login events and trigger alerts:

- **send_email**: Sends an email alert through the configured SMTP server.
- **send_sms**: Sends an SMS alert using Twilio.
- **log_alert**: Logs login attempts and prevents duplicate alerts within a 5-minute window.
- **should_alert**: Checks if a recent alert was sent for the same user/IP combination.
- **monitor_log**: Monitors the log file in real-time for SSH events.
- **alert_login**: Triggers when a successful SSH login is detected.
- **alert_login_failed**: Triggers when a failed SSH login attempt is detected.

## 5. Error Handling and Troubleshooting

- **SMTP Errors**: Verify the email address and password in `config.json`. Ensure less secure app access is enabled in your email settings if required.
- **Twilio Errors**: Verify the Twilio credentials and ensure the phone number format is correct.
- **Log File Errors**: Ensure the specified log file path exists and the user running the script has read permissions.
- **Stopping the Service**: The script listens for termination signals (`SIGINT` and `SIGTERM`). When `sudo systemctl stop sshalert` or `service sshalert stop` is run, the script will exit gracefully.

## 6. Dependencies

This script depends on the following libraries:
- `smtplib`: For sending emails (built-in).
- `twilio`: Install with `pip install twilio` for SMS functionality.