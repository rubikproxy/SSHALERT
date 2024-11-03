sudo apt install rsyslog python3 python3-pip
sudo ln -s /ssh_login_alert/sshalert.service /etc/systemd/system/sshalert.service
sudo ln -s /ssh_login_alert/sshalert /etc/init.d/sshalert
sudo chmod +x /etc/init.d/sshalert