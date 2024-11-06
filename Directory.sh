#!/bin/bash

LOG_DIRECTORY="/var/log/SSH-Alert"
LOG_FILE_PATH="$LOG_DIRECTORY/sshalert.log"

create_directory() {
    if [ ! -d "$LOG_DIRECTORY" ]; then
        echo "[*] Log directory not found. Attempting to create it."
        mkdir -p "$LOG_DIRECTORY" && \
        chmod 755 "$LOG_DIRECTORY" && \
        chown root:root "$LOG_DIRECTORY"
        
        if [ $? -eq 0 ]; then
            echo "[*] Created log directory: $LOG_DIRECTORY"
        else
            echo "[!] Failed to create log directory."
            return 1
        fi
    fi
    if [ ! -f "$LOG_FILE_PATH" ]; then
        echo "[*] Log file not found. Attempting to create it."
        touch "$LOG_FILE_PATH" && \
        chmod 644 "$LOG_FILE_PATH" && \
        chown root:root "$LOG_FILE_PATH"
        
        if [ $? -eq 0 ]; then
            echo "[*] Created log file: $LOG_FILE_PATH"
        else
            echo "[!] Failed to create log file."
            return 1
        fi
    fi
    
    return 0
}

create_directory
