import os
import json
import time
import signal
import requests
import logging
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
import subprocess

# def create_log_directory():
#     log_directory = '/var/log/SSH-Alert'
#     log_file_path = os.path.join(log_directory, 'sshalert.log')
    
#     if not os.path.exists(log_directory):
#         try:
#             os.makedirs(log_directory)
#             os.chmod(log_directory, 0o755)
#             logging.info(f"[*] Created log directory: {log_directory}")
#         except Exception as e:
#             logging.error(f"[!] Failed to create log directory: {str(e)}")
#             exit(1)
#     else:
#         logging.info(f"[*] Log directory already exists: {log_directory}")

#     if not os.path.exists(log_file_path):
#         try:
#             with open(log_file_path, 'a') as f:
#                 pass
#             os.chmod(log_file_path, 0o644)  # File permission
#             logging.info(f"[*] Created log file: {log_file_path}")
#         except Exception as e:
#             logging.error(f"[!] Failed to create log file: {str(e)}")
#             exit(1)
#     else:
#         logging.info(f"[*] Log file already exists: {log_file_path}")

#     try:
#         os.chown(log_directory, 0, 0)
#         os.chown(log_file_path, 0, 0)
#     except PermissionError:
#         logging.error("[!] Permission denied: Unable to change ownership of log files.")
#     except Exception as e:
#         logging.error(f"[!] Error changing ownership: {str(e)}")
        
#     return log_file_path

def create_directory():
    log_directory = '/var/log/SSH-Alert'
    log_file_path = os.path.join(log_directory, 'sshalert.log')

    # Attempt to create the log directory
    if not os.path.exists(log_directory):
        logging.info("[*] Log directory not found. Attempting to create it.")
        try:
            os.makedirs(log_directory, exist_ok=True)
            os.chmod(log_directory, 0o755)
            os.chown(log_directory, 0, 0)
            logging.info(f"[*] Created log directory: {log_directory}")
        except Exception as e:
            logging.error(f"[!] Failed to create log directory: {str(e)}")
            return None

    # Attempt to create the log file
    if not os.path.exists(log_file_path):
        logging.info("[*] Log file not found. Attempting to create it.")
        try:
            with open(log_file_path, 'w') as f:
                pass
            os.chmod(log_file_path, 0o644)
            os.chown(log_file_path, 0, 0)
            logging.info(f"[*] Created log file: {log_file_path}")
        except Exception as e:
            logging.error(f"[!] Failed to create log file: {str(e)}")
            return None

    return log_file_path


def setuplog():
    log_file_path = '/var/log/SSH-Alert/sshalert.log'

    if not logging.getLogger().hasHandlers():
        try:
            log_handler = RotatingFileHandler(log_file_path, maxBytes=10*1024*1024, backupCount=5)
            log_handler.setLevel(logging.INFO)

            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            log_handler.setFormatter(formatter)

            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            logger.addHandler(log_handler)

            # logging.info(f"[*] Log file set up: {log_file_path}")
        except Exception as e:
            logging.error(f"[!] Failed to set up log file: {str(e)}")
    return log_file_path

log_file_path = setuplog()
logging.basicConfig(
    filename=log_file_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def is_service_installed(service_name):
    try:
        result = subprocess.run(['systemctl', 'list-unit-files'], capture_output=True, text=True)
        if service_name in result.stdout:
            # logging.info(f"[*] {service_name} is installed.")
            return True
        else:
            logging.error(f"[!] {service_name} is not installed.")
            return False
    except Exception as e:
        logging.error(f"[!] Error checking if {service_name} is installed: {str(e)}")
        return False

def check_sshd():
    if not is_service_installed('ssh.service'):
        logging.error("[!] Please install the SSH server.")
        return

    sshd_status = subprocess.run(['sudo', 'service', 'ssh', 'status'], capture_output=True, text=True)

    if "active (running)" in sshd_status.stdout:
        logging.info("[*] SSH server is already running.")
        return

    logging.error("[!] SSH server is not running. Attempting to start the SSH server...")
    
    start_sshd = subprocess.run(['sudo', 'service', 'ssh', 'start'], capture_output=True, text=True)
    
    if start_sshd.returncode == 0:
        logging.info("[*] SSH server started successfully.")
    else:
        logging.error(f"[!] Failed to start SSH server. Error: {start_sshd.stderr.strip()}")
        exit(1)

def check_and_manage_rsyslog():
    if not is_service_installed('rsyslog.service'):
        logging.error("[!] Please install the rsyslog service.")
        return
    
    pid_file = '/var/run/rsyslogd.pid'
    if os.path.exists(pid_file):
        # logging.info(f"[*] Found PID file at {pid_file}. Checking its contents...")
        with open(pid_file, 'r') as f:
            pid = f.read().strip()
        try:
            process_check = subprocess.run(['ps', 'axu'], capture_output=True, text=True)
            if pid in process_check.stdout:
                # logging.info(f"[*] rsyslogd is already running with PID: {pid}")
                return
            else:
                logging.warning(f"[!] PID {pid} does not correspond to rsyslogd. Cleaning up PID file...")
                os.remove(pid_file)

        except Exception as e:
            logging.error(f"[!] Error checking processes: {str(e)}")
            return

    logging.info("[*] Attempting to start rsyslogd service...")
    start_command = subprocess.run(['sudo', 'rsyslogd'], capture_output=True, text=True)

    if start_command.returncode == 0:
        logging.info("[*] rsyslogd service started successfully.")
    else:
        logging.error(f"[!] Failed to start rsyslogd service. Error: {start_command.stderr.strip()}")
        logging.error("[!] Please check /var/log/daemon.log and other log files for errors.")


path_config = "/var/labsstorage/home/vinsanjay/SSHALERT/config.json"

try:
    with open(path_config) as config_file:
        config = json.load(config_file)
except FileNotFoundError:
    logging.error("[!] Configuration file not found. Exiting...")
    logging.info(f"Expected location: {path_config}")
    exit(1)
except json.JSONDecodeError:
    logging.error("[!] Error decoding JSON from configuration file. Exiting...")
    exit(1)
except PermissionError:
    logging.error("[!] Permission denied when accessing the configuration file. Exiting...")
    exit(1)
except Exception as e:
    logging.error(f"[!] An unexpected error occurred: {e}. Exiting...")
    exit(1)

TELEGRAM_TOKEN = config.get('telegram', {}).get('bot_token')
CHAT_ID = config.get('telegram', {}).get('chat_id')
LOG_FILE_PATH = config.get('log', {}).get('file_path', '')

if not TELEGRAM_TOKEN or not CHAT_ID:
    logging.error("[!] Telegram bot token or chat ID missing in configuration. Exiting...")
    exit(1)

alert_log = []
alert_limit_time = timedelta(minutes=5)
last_alert_time = {}
running = True

def signal_handler(sig, frame):
    global running
    running = False
    try:
        log_to_file("System", "[*] Stopping SSH alert...")
    except Exception as e:
        logging.error(f"Error stopping SSH alert: {e}")

def send_telegram_message(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {'chat_id': CHAT_ID, 'text': text, 'parse_mode': 'HTML'}
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        logging.error("[!] Network error: Unable to connect to Telegram API.")
    except requests.exceptions.Timeout:
        logging.error("[!] Timeout error: Telegram API request timed out.")
    except requests.exceptions.RequestException as e:
        logging.error(f"[!] Telegram API error: {e}")

def log_alert(user, ip):
    timestamp = datetime.now()
    alert_log[:] = [(u, i, t) for u, i, t in alert_log if (u, i) != (user, ip) or t > timestamp - alert_limit_time]
    alert_log.append((user, ip, timestamp))

def clear_failed_attempts(user, ip):
    timestamp = datetime.now()
    alert_log[:] = [(u, i, t) for u, i, t in alert_log if not (u == user and i == ip and t > timestamp - alert_limit_time)]

def should_alert(user, ip):
    timestamp = datetime.now()
    return not any(u == user and i == ip and t > timestamp - alert_limit_time for u, i, t in alert_log)


def alert_login(user, ip):
    clear_failed_attempts(user, ip)
    current_time = datetime.now()
    if (user, ip) in last_alert_time:
        if current_time - last_alert_time[(user, ip)] < alert_limit_time:
            return
    last_alert_time[(user, ip)] = current_time
    if should_alert(user, ip):
        message = f"""
        🚀 SSH-Login Alert 🚀
        ``` 
        User: {user}
        IP: {ip}
        Time: {current_time.strftime('%Y-%m-%d %H:%M:%S')}
        ```"""
        send_telegram_message(message)
        log_alert(user, ip)
        log_to_file("SSH-Login Successful", f"User: {user}, IP: {ip}")
        logging.info(f"[*] SSH-Login Successful - User: {user}, IP: {ip}")

def alert_login_failed(user, ip):
    if should_alert(user, ip):
        message = f"""
        ❗SSH-login Failed Attempt❗
        ``` 
        User: {user}
        IP: {ip}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        ```"""
        send_telegram_message(message)
        log_alert(user, ip)
        log_to_file("SSH-Login Failed Attempt", f"User: {user}, IP: {ip}")
        logging.warning(f"[!] SSH-Login Failed Attempt - User: {user}, IP: {ip}")
def log_to_file(subject, body):
    logging.info(f"{subject} - {body}")

def monitor_log():
    global running
    logging.info("[*] Starting SSH alert...")

    try:
        with open(LOG_FILE_PATH, 'r') as f:
            f.seek(0, os.SEEK_END)
            while running:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                
                if 'sshd' in line:
                    parts = line.split()
                    if 'Accepted' in line and 'for' in parts and 'from' in parts:
                        try:
                            user_index = parts.index('for') + 1
                            ip_index = parts.index('from') + 1
                            user = parts[user_index]
                            ip = parts[ip_index]
                            alert_login(user, ip)
                            logging.info(f"[*] SSH-Login Successful - User: {user}, IP: {ip}")
                        except (IndexError, ValueError) as e:
                            logging.warning(f"[!] Unexpected format in Accepted line: {line.strip()} - {e}")

                    elif 'Failed' in line and 'for' in parts and 'from' in parts:
                        try:
                            user_index = parts.index('for') + 1
                            ip_index = parts.index('from') + 1
                            user = parts[user_index]
                            ip = parts[ip_index]
                            alert_login_failed(user, ip)
                            logging.info(f"[*] SSH-Login Failed - User: {user}, IP: {ip}")
                        except (IndexError, ValueError) as e:
                            logging.warning(f"[!] Unexpected format in Failed line: {line.strip()} - {e}")
                    else:
                        # Log if the line does not match expected SSH login formats
                        logging.warning(f"[!] Unprocessed sshd line format: {line.strip()}")
    except Exception as e:
        logging.error(f"[!] Error reading log file: {e}")
        exit(1)
        
if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            logging.error("[!] This script must be run as root. Use 'sudo' to run it.")
            exit(1)
        setuplog()
        if not create_directory():
            logging.error("[!] Failed to set up the logging directory or file.")
            exit(1)
        
        check_sshd()
        check_and_manage_rsyslog()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        monitor_log()
    except Exception as e:
        logging.error(f"[!] Critical error encountered: {e}")
        exit(1)
