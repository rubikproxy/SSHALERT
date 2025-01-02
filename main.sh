#!/bin/bash

TARGET_USER="root"
TARGET_HOME="/home/$TARGET_USER"
CONFIG_PATH="$TARGET_HOME/.sshalert/config.json"

get_input() {
    if [ ! -d "$TARGET_HOME/.sshalert" ]; then
        sudo mkdir -p "$TARGET_HOME/.sshalert"
        sudo chown "$TARGET_USER:$TARGET_USER" "$TARGET_HOME/.sshalert"
    fi
    if [ ! -f "$CONFIG_PATH" ]; then
        read -p "Enter Telegram Bot Token: " bot_token
        read -p "Enter Telegram Chat ID: " chat_id

        config_json=$(cat <<EOF
{
    "telegram": {
        "bot_token": "$bot_token",
        "chat_id": "$chat_id"
    },
    "log": {
        "file_path": "/var/log/auth.log"
    }
}
EOF
        )
        echo "$config_json" | sudo tee "$CONFIG_PATH" > /dev/null
        sudo chown "$TARGET_USER:$TARGET_USER" "$CONFIG_PATH"
        echo "Configuration saved to $CONFIG_PATH"
    else
        echo "Configuration file already exists at $CONFIG_PATH. Skipping creation."
    fi
}

setup_permissions() {
    sudo chmod 644 "$CONFIG_PATH"
    sudo chown "$TARGET_USER:$TARGET_USER" "$CONFIG_PATH"
}

install_dependencies() {
    sudo apt update
    sudo apt install -y rsyslog python3 python3-pip
}
setup_service() {
    sudo mkdir -p /etc/sshalert/source
    sudo mkdir -p /etc/sshalert/conf
    sudo cp -r sshalert sshalert.service /etc/sshalert/conf 
    sudo cp -r main.py Directory.sh LICENSE requirements.txt /etc/sshalert/source
    pip install -r /etc/sshalert/source/requirements.txt
    if [ -L /etc/systemd/system/sshalert.service ]; then
        sudo rm -rf /etc/systemd/system/sshalert.service
    fi
    sudo ln -s /etc/sshalert/conf/sshalert.service /etc/systemd/system/sshalert.service
    if [ ! -f /etc/init.d/sshalert ]; then
        sudo cp /etc/sshalert/conf/sshalert /etc/init.d/sshalert
    fi
    sudo chmod +x /etc/init.d/sshalert
    sudo update-rc.d sshalert defaults
    sudo systemctl enable sshalert.service
}

get_input
setup_permissions
install_dependencies
setup_service

echo "Setup completed successfully."
