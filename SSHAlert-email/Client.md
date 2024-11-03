
# SSH Alert Monitoring Service - Client Documentation

## Overview

The **SSH Alert Monitoring Service** is a security monitoring tool designed to alert users about SSH login attempts on their server. Clients receive email and SMS notifications for each login or failed login attempt, allowing for proactive security monitoring.

## Table of Contents
1. [Setting Up Notifications](#setting-up-notifications)
2. [Using the Alert Service](#using-the-alert-service)
3. [Receiving Alerts](#receiving-alerts)
4. [Alert Frequency and Limits](#alert-frequency-and-limits)
5. [Stopping Alerts](#stopping-alerts)
6. [Troubleshooting](#troubleshooting)

## 1. Setting Up Notifications

1. **Email and SMS Configuration**: To start receiving alerts, configure your email and phone number in the `config.json` file provided by the server administrator. This file includes:

   ```json
   {
     "email": {
       "to": "your-email@example.com"
     },
     "twilio": {
       "to_phone_number": "+1234567890"
     }
   }
   ```

2. **Alert Types**: Alerts are sent for both successful and failed SSH login attempts, which can help monitor authorized and unauthorized access attempts.

3. **Log File Monitoring**: The system checks the SSH log file (`/var/log/auth.log`) to detect login attempts. Alerts are only sent when login or authentication activities occur.

4. **Service Availability**: Confirm that the SSH Alert Monitoring Service is active on your server. The server administrator can verify this with:

   ```bash
   sudo systemctl status sshalert
                or
   sudo service sshalert status
   ```

## 2. Using the Alert Service

Once the setup is complete:
1. **Monitor Login Events**: The service will track each login attempt and notify you of both successful and failed attempts.
2. **Frequency Limiting**: To prevent repeated notifications, the service limits alerts to one per user/IP combination every 5 minutes.

## 3. Receiving Alerts

You will receive:
- **Email Alerts**: An email notification will include the user name, IP address, and timestamp for each login event.
- **SMS Alerts**: An SMS notification will provide similar information, helping you stay informed about login events when email access may not be convenient.

### Example Alert Content

**Email Alert**
- **Subject**: SSH Login Alert
- **Content**:
  ```
  User: username
  IP Address: 123.45.67.89
  Timestamp: YYYY-MM-DD HH:MM:SS
  ```

**SMS Alert**
  ```
  SSH Alert: User [username] logged in from IP [123.45.67.89] at [YYYY-MM-DD HH:MM:SS].
  ```

## 4. Alert Frequency and Limits

To reduce repetitive notifications:
- **5-Minute Alert Limit**: You’ll only receive one alert per user/IP combination within a 5-minute window.
- **Real-Time Monitoring**: The service continuously monitors the log file, so alerts are nearly real-time but limited to avoid spam.

## 5. Stopping Alerts

If you no longer want to receive alerts, contact your server administrator and request them to stop the SSH Alert Monitoring Service.

Alternatively, if you have access, run:
```bash
sudo systemctl stop sshalert
```

## 6. Troubleshooting

### Common Issues

- **Email/SMS Alerts Not Received**:
  - Verify the accuracy of your email and phone number in `config.json`.
  - Ensure Twilio SMS credits are available and that the sender number is correct.
  - Check your email's spam folder for missing emails.

- **Alert Frequency Concerns**:
  - Alerts should be received only once every 5 minutes per user/IP. If receiving alerts too frequently, contact the server administrator.

- **Service Not Running**:
  - If no alerts are received, confirm the service is active on your server. The administrator can verify this with:
    ```bash
    sudo systemctl status sshalert
    ```