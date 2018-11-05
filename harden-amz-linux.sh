#!/bin/bash

yum update -y --security

# ----------------- Kernel Section --------------------
# 3.3.1 no accept ipv6 routes
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

# 3.2.4 Suspicious packets are logged
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

# 3.2.3 icmp redirects
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

# 3.1.2 packet redirect
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

# ------------------ SSH Section --------------------------
# 5.2.5 set max auth tries to 4 or less
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
# 5.2.11 Approved MAC algo
echo 'macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' >> /etc/ssh/sshd_config
# 5.2.3 Log Level
sed -i 's/#\(LogLevel INFO\)/\1/' /etc/ssh/sshd_config
# 5.2.2 SSH 2 only explicit
sed -i 's/#\(Protocol 2\)/\1/' /etc/ssh/sshd_config
/etc/init.d/sshd reload

# ------------------ Password Settings ---------------------
# 5.4.1.4 deactivate in active accounts - Set for new accounts not ec2-user
useradd -D -f 30
# 5.3.1 PW strenght
sed -i 's/# \(minlen =\) 9/\1 14/' /etc/security/pwquality.conf
sed -i 's/# \(dcredit =\) 1/\1 -1/' /etc/security/pwquality.conf
sed -i 's/# \(ucredit =\) 1/\1 -1/' /etc/security/pwquality.conf
sed -i 's/# \(ocredit =\) 1/\1 -1/' /etc/security/pwquality.conf
sed -i 's/# \(lcredit =\) 1/\1 -1/' /etc/security/pwquality.conf




# ------------------ Audit Daemon Config --------------------
# 4.1.1.2 audit config
sed -i 's/space_left_action = SYSLOG/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/action_mail_acct = root/action_mail_acct = support@rightbrainnetworks.com/' /etc/audit/auditd.conf
sed -i 's/admin_space_left_action = SUSPEND/admin_space_left_action = halt/' /etc/audit/auditd.conf

# 4.1.18 audit not to be modified without reboot
echo "-e 2" >> /etc/audit/audit.rules

# 4.1.6 events that modify network are collected
echo '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' >> /etc/audit/audit.rules
echo '-w /etc/issue -p wa -k system-locale' >> /etc/audit/audit.rules
echo '-w /etc/issue.net -p wa -k system-locale' >> /etc/audit/audit.rules
echo '-w /etc/hosts -p wa -k system-locale' >> /etc/audit/audit.rules
echo '-w /etc/sysconfig/network -p wa -k system-locale' >> /etc/audit/audit.rules

# ------------------ Cron Modes ---------------------------
# 5.1.3 Cron mode hourly
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
# 5.1.3 Cron mode .d
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# ------------------ File Systems --------------------------
# 1.1.1.1 No cramfs
echo 'install cramfs /bin/true' > /etc/modprobe.d/CIS.conf
# 1.1.1.8 No FAT
echo 'install vfat /bin/true' >> /etc/modprobe.d/CIS.conf
# 1.1.1.4 No hfs
echo 'install hfs /bin/true' >> /etc/modprobe.d/CIS.conf

# ------------------ Yum -------------------------
# 1.2.3 gpg checks
sed -i 's/gpgcheck=0/gpgcheck=1/' /etc/yum.repos.d/amzn-nosrc.repo



# 1.3.1 install and configure AIDE
yum install -y aide
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

sed -i 's/\(tmpfs   defaults\)/\1,noexec/' /etc/fstab
mount -o remount,noexec /dev/shm

# 1.7.1.2 Informational message of the day issue
grep -v 'Kernel \r on an \m' /etc/issue > /etc/issue.new
mv /etc/issue.new /etc/issue
echo 'Authorized uses only. All activity may be monitored and reported.' >> /etc/issue
