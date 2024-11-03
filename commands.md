sudo rsyslogd
rsyslogd -v
sudo systemctl start rsyslog
Ensure there’s a line that directs authentication logs to /var/log/auth.log, like:
auth,authpriv.*    /var/log/auth.log
sudo nano /etc/rsyslog.conf
sudo grep "sshd" /var/log/auth.log
sudo ln -s /home/rubikproxy/developer/rubikproxy-portfolio/Python/API-PRODUCTION/ssh_login_alart/sshalert.service /etc/systemd/system/
sudo ln -s /home/rubikproxy/developer/rubikproxy-portfolio/Python/API-PRODUCTION/ssh_login_alart/sshalert /etc/init.d/sshalert
sudo chmod +x /etc/init.d/sshalert
ps aux | grep sshalert
tail -f /var/log/syslog | grep sshalert
sudo update-rc.d sshalert defaults
tail -f /home/rubikproxy/developer/rubikproxy-portfolio/Python/API-PRODUCTION/ssh_login_alart/alerts.log