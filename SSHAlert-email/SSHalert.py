import os
import smtplib
from twilio.rest import Client
from datetime import datetime, timedelta
import time
import json

# Load settings from a config file
with open('config.json') as config_file:
    config = json.load(config_file)

EMAIL_ADDRESS = config['email']['address']
EMAIL_PASSWORD = config['email']['password']
TO_EMAIL = config['email']['to']

TWILIO_ACCOUNT_SID = config['twilio']['account_sid']
TWILIO_AUTH_TOKEN = config['twilio']['auth_token']
TWILIO_PHONE_NUMBER = config['twilio']['phone_number']
TO_PHONE_NUMBER = config['twilio']['to_phone_number']

LOG_FILE_PATH = config['log']['file_path']
alert_log = []
alert_limit_time = timedelta(minutes=5)  # Time frame to limit alerts

def send_email(subject, body):
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            msg = f'Subject: {subject}\nContent-Type: text/html\n\n{body}'
            smtp.sendmail(EMAIL_ADDRESS, TO_EMAIL, msg)
    except Exception as e:
        print(f"Error sending email: {e}")

def send_sms(body):
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(body=body, from_=TWILIO_PHONE_NUMBER, to=TO_PHONE_NUMBER)
    except Exception as e:
        print(f"Error sending SMS: {e}")

def log_alert(user, ip):
    timestamp = datetime.now()
    alert_log.append((user, ip, timestamp))
    alert_log[:] = [alert for alert in alert_log if alert[2] > timestamp - alert_limit_time]

def should_alert(user, ip):
    for u, i, t in alert_log:
        if u == user and i == ip:
            return False
    return True

def alert_login(user, ip):
    if should_alert(user, ip):
        subject = "SSH Login Alert"
        body = f"<p>User <strong>{user}</strong> logged in from IP <strong>{ip}</strong> at {datetime.now()}.</p>"
        send_email(subject, body)
        send_sms(f"User {user} logged in from IP {ip} at {datetime.now()}.")
        log_alert(user, ip)
        log_to_file(subject, body)

def log_to_file(subject, body):
    with open('alerts.log', 'a') as log_file:
        log_file.write(f"{datetime.now()} - {subject}\n{body}\n\n")

def monitor_log():
    try:
        with open(LOG_FILE_PATH, 'r') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                if 'sshd' in line:
                    parts = line.split()
                    if 'Accepted' in line:
                        user = parts[8]
                        ip = parts[-4]
                        alert_login(user, ip)
                    elif 'Failed' in line:
                        user = parts[8]
                        ip = parts[-4]
                        alert_login_failed(user, ip)
    except Exception as e:
        print(f"Error monitoring log: {e}")

def alert_login_failed(user, ip):
    subject = "SSH Failed Login Attempt"
    body = f"<p>Failed login attempt by <strong>{user}</strong> from IP <strong>{ip}</strong> at {datetime.now()}.</p>"
    send_email(subject, body)
    send_sms(f"Failed login attempt by {user} from IP {ip} at {datetime.now()}.")
    log_to_file(subject, body)

if __name__ == "__main__":
    monitor_log()
