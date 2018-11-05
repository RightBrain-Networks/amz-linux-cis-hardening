#!/bin/bash

yum update -y --security

# 3.3.1 no accept ipv6 routes
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

# 5.2.5 set max auth tries to 4 or less
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
/etc/init.d/sshd reload

# 4.1.1.2 audit config
sed -i 's/space_left_action = SYSLOG/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/action_mail_acct = root/action_mail_acct = support@rightbrainnetworks.com/' /etc/audit/auditd.conf
sed -i 's/admin_space_left_action = SUSPEND/admin_space_left_action = halt/' /etc/audit/auditd.conf
# 4.1.18 audit not to be modified without reboot
echo "-e 2" >> /etc/audit/audit.rules
/etc/audit/audit.rules

# 5.1.3 Cron mode
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

sed -i 's/\(tmpfs   defaults\)/\1,noexec/' /etc/fstab
mount -o remount,noexec /dev/shm

grep -v 'Kernel \r on an \m' /etc/issue > /etc/issue.new
mv /etc/issue.new /etc/issue
echo 'Authorized uses only. All activity may be monitored and reported.' >> /etc/issue
