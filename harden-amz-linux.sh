#!/bin/bash

yum update -y --security

# ----------------- Kernel Section --------------------
# 1.5.1 core dumps restricted
echo '* hard core 0' > /etc/security/limits.d/coredumpsrestricted
echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0

# 3.1.2 packet redirect
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

# 3.3.1 no accept ipv6 routes
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

# 3.3.2 No ICMP redirects ip6
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1

# 3.2.4 Suspicious packets are logged
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

# 3.2.3 icmp redirects
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

# 3.2.3 icmp secure redirects
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

# 3.2.7 Reverse Path Filtering is enabled
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf


# ------------------ SSH Section --------------------------
# 5.2.1 mod sshconfig
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

# 5.2.5 set max auth tries to 4 or less
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config

# 5.2.6 sshd_config file IgnoreRhosts yes
echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config
# 5.2.10 PermitUserEnvironment
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config

# 5.2.4
sed -i 's/#ForwardX11 no/ForwardX11 no/' /etc/ssh/sshd_config

# 5.2.7 disable hostbased auth
sed -i 's/#\(HostbasedAuthentication no\)/\1/' /etc/ssh/sshd_config

# 5.2.9 disable empty passwords
sed -i 's/#\(PermitEmptyPasswords no\)/\1/' /etc/ssh/sshd_config

# 5.2.11 Approved MAC algo
echo 'macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' >> /etc/ssh/sshd_config

# 5.2.12 Idle timeout
sed -i 's/#\(ClientAliveInterval\) 0/\1 300/' /etc/ssh/sshd_config
sed -i 's/#\(ClientAliveCountMax\) 3/\1 0/' /etc/ssh/sshd_config

# 5.2.14 Only allow Certain users to login via ssh
echo 'AllowUsers ec2-user' >> /etc/ssh/sshd_config

# 5.2.3 Log Level
sed -i 's/#\(LogLevel INFO\)/\1/' /etc/ssh/sshd_config

# 5.2.2 SSH 2 only explicit
sed -i 's/#\(Protocol 2\)/\1/' /etc/ssh/sshd_config

# 5.2.13 LoginGraceTime
sed -i 's/#\(LoginGraceTime\) 2m/\1 60/' /etc/ssh/sshd_config

# 5.2.15 Banner configured
sed -i 's/#\(Banner\) none/\1 \/etc\/issue.net/' /etc/ssh/sshd_config

# 5.2.8 No Root Login
sed -i 's/#\(PermitRootLogin\) yes/\1 no/' /etc/ssh/sshd_config

# Reload config after changes
/etc/init.d/sshd reload

# 5.4.4 umask
echo 'umask 027' >> /etc/profile 
echo 'umask 027' >> /etc/bashrc

# 5.4.5 Session Timeout
echo -e "TMOUT=600\nreadonly TMOUT\nexport TMOUT" >> /etc/profile
echo -e "TMOUT=600\nreadonly TMOUT\nexport TMOUT" >> /etc/bashrc

# 5.5 su command is restricted
sed -i 's/#\(auth.*required.*pam_wheel.so use_uid\)/\1/' /etc/pam.d/su
sed -i 's/\(wheel:x:10:ec2-user\)/\1,root/' /etc/group

# ------------------ Password Settings ---------------------
# 5.3.2 Lockout after failed password attempts
echo 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900' >> /etc/pam.d/password-auth-ac
echo 'auth [success=1 default=bad] pam_unix.so' >> /etc/pam.d/password-auth-ac
echo 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' >> /etc/pam.d/password-auth-ac
echo 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900' >> /etc/pam.d/password-auth-ac
echo 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900' >> /etc/pam.d/system-auth-ac
echo 'auth [success=1 default=bad] pam_unix.so' >> /etc/pam.d/system-auth-ac
echo 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' >> /etc/pam.d/system-auth-ac
echo 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900' >> /etc/pam.d/system-auth-ac

# 5.3.3 PW remember 
sed -i 's/\(password *sufficient *pam_unix.so.*\)/\1 remember=5/' /etc/pam.d/password-auth-ac
sed -i 's/\(password *sufficient *pam_unix.so.*\)/\1 remember=5/' /etc/pam.d/system-auth-ac
# 5.3.1 PW strenght
sed -i 's/# \(minlen =\) 9/\1 14/' /etc/security/pwquality.conf
sed -i 's/# \(dcredit =\) 1/\1 -1/' /etc/security/pwquality.conf
sed -i 's/# \(ucredit =\) 1/\1 -1/' /etc/security/pwquality.conf
sed -i 's/# \(ocredit =\) 1/\1 -1/' /etc/security/pwquality.conf
sed -i 's/# \(lcredit =\) 1/\1 -1/' /etc/security/pwquality.conf

# reload auth config after changes 
/usr/sbin/authconfig --update

# 5.4.1.1 password expires after 90 days
sed -i 's/\(PASS_MAX_DAYS\)   99999/\1 90/' /etc/login.defs

# 5.4.1.4 deactivate in active accounts - Set for new accounts not ec2-user
useradd -D -f 30
# 5.4.1.2 Min days between password changes
sed -i 's/\(PASS_MIN_DAYS  \) 0/\1 7/' /etc/login.defs



# ------------------ Audit Daemon Config --------------------
# 4.1.1.2 audit config
sed -i 's/space_left_action = SYSLOG/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/action_mail_acct = root/action_mail_acct = support@rightbrainnetworks.com/' /etc/audit/auditd.conf
sed -i 's/admin_space_left_action = SUSPEND/admin_space_left_action = halt/' /etc/audit/auditd.conf

# 4.1.1.3 dont delete audit logs
sed -i 's/\(max_log_file_action =\) ROTATE/\1 keep_logs/' /etc/audit/auditd.conf


# 4.1.4 events that modify date time are collected
echo '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b64 -S clock_settime -k time-change' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S clock_settime -k time-change' >> /etc/audit/audit.rules
echo '-w /etc/localtime -p wa -k time-change' >> /etc/audit/audit.rules

# 4.1.5 events that modify user group info are collected
echo '-w /etc/group -p wa -k identity' >> /etc/audit/audit.rules
echo '-w /etc/passwd -p wa -k identity' >> /etc/audit/audit.rules
echo '-w /etc/gshadow -p wa -k identity' >> /etc/audit/audit.rules
echo '-w /etc/shadow -p wa -k identity' >> /etc/audit/audit.rules
echo '-w /etc/security/opasswd -p wa -k identity' >> /etc/audit/audit.rules


# 4.1.6 events that modify network are collected
echo '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' >> /etc/audit/audit.rules
echo '-w /etc/issue -p wa -k system-locale' >> /etc/audit/audit.rules
echo '-w /etc/issue.net -p wa -k system-locale' >> /etc/audit/audit.rules
echo '-w /etc/hosts -p wa -k system-locale' >> /etc/audit/audit.rules
echo '-w /etc/sysconfig/network -p wa -k system-locale' >> /etc/audit/audit.rules

# 4.1.8 Ensure logins and outs are collected 
echo '-w /var/log/lastlog -p wa -k logins' >> /etc/audit/audit.rules
echo '-w /var/run/faillock/ -p wa -k logins' >> /etc/audit/audit.rules

# 4.1.9 session init info is collected
echo '-w /var/run/utmp -p wa -k session' >> /etc/audit/audit.rules
echo '-w /var/log/wtmp -p wa -k logins' >> /etc/audit/audit.rules
echo '-w /var/log/btmp -p wa -k logins' >> /etc/audit/audit.rules

# 4.1.10 discretionary access control permission modification events are collected
echo '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules

# 4.1.11 unsuccessful unauthorized file access attempts are collected
echo '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access' >> /etc/audit/audit.rules  

# 4.1.13 successful file system mounts are collected
echo '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts' >> /etc/audit/audit.rules
echo '-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts' >> /etc/audit/audit.rules


# 4.1.14
echo '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete' >> /etc/audit/audit.rules

# 4.1.15 changes to system admin scope are collected
echo '-w /etc/sudoers -p wa -k scope' >> /etc/audit/audit.rules
echo '-w /etc/sudoers.d/ -p wa -k scope' >> /etc/audit/audit.rules

# 4.1.16 system admin action sudo log are collected
echo '-w /var/log/sudo.log -p wa -k actions' >> /etc/audit/audit.rules

# 4.1.17 kernel module loading and unloadedin is collected
echo '-w /sbin/insmod -p x -k modules' >> /etc/audit/audit.rules
echo '-w /sbin/rmmod -p x -k modules' >> /etc/audit/audit.rules
echo '-w /sbin/modprobe -p x -k modules' >> /etc/audit/audit.rules
echo '-a always,exit arch=b64 -S init_module -S delete_module -k modules' >> /etc/audit/audit.rules

# 4.1.18 audit not to be modified without reboot
echo "-e 2" >> /etc/audit/audit.rules

# Reload auditd
/etc/init.d/auditd reload

# 4.1.3 Grub audit before auditd
sed -i 's/$\(kernel.*\)/\1 audit=1/' /boot/grub/menu.lst

# 1.4.1 Grub permissions
chown root:root /boot/grub/menu.lst 
chmod og-rwx /boot/grub/menu.lst

# ------------------ Cron Modes ---------------------------
# 5.1.2 Crontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
# 5.1.3 Cron mode hourly
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
# 5.1.4 Cron mode .d
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# 5.1.4 Cron mode daily
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

# 5.1.5 Cron mode .weekly
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
# 5.1.6 Cron mode .monthly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

# 5.1.8 atcron for authorized only
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

# ------------------ NTP and basic Services ----------------
# 2.2.1.2 NTP
echo 'restrict -4 default kod nomodify notrap nopeer noquery' >> /etc/ntp.conf
echo 'restrict -6 default kod nomodify notrap nopeer noquery' >> /etc/ntp.conf
sed -i 's/\(OPTIONS="-g\)\("\)/\1 -u ntp:ntp\2/' /etc/sysconfig/ntpd

# ------------------ File Systems --------------------------
# 1.1.1.1 No cramfs
echo 'install cramfs /bin/true' > /etc/modprobe.d/CIS.conf
# 1.1.1.4 No hfs
echo 'install hfs /bin/true' >> /etc/modprobe.d/CIS.conf


# 1.1.1.3 No jffs2
echo 'install jffs2 /bin/true' >> /etc/modprobe.d/CIS.conf


# 1.1.1.5 No hfsplus
echo 'install hfsplus /bin/true' >> /etc/modprobe.d/CIS.conf
# 1.1.1.6 No squashfs
echo 'install squashfs /bin/true' >> /etc/modprobe.d/CIS.conf
# 1.1.1.7 No udf
echo 'install udf /bin/true' >> /etc/modprobe.d/CIS.conf
# 1.1.1.8 No FAT
echo 'install vfat /bin/true' >> /etc/modprobe.d/CIS.conf

# 1.3.2 filesystem integrity is regularly checked
crontab -u root -e Add the following line to the crontab: 0 5 * * * /usr/sbin/aide --check

# 1.4.3 No interactive boot
sed -i 's/PROMPT=yes/PROMPT=no/' /etc/sysconfig/init

# 2.2.7 NFS and RPC
chkconfig nfs off
chkconfig rpcbind off


# ------------------ Yum -------------------------
# 1.2.3 gpg checks
sed -i 's/gpgcheck=0/gpgcheck=1/' /etc/yum.repos.d/amzn-nosrc.repo

# ------------------ Logs ------------------------
find /var/log -type f -exec chmod g-wx,o-rwx {} +

# 4.2.1.3 rsyslog file perms
echo '$FileCreateMode 0640' >> /etc/rsyslog.conf

# 1.3.1 install and configure AIDE
yum install -y aide
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 2.2.2 No X windows
yum remove -y xorg-x11*

# 1.1.15 nodev option
# 1.1.14 noexec option
# 1.1.16 nosuid option
sed -i 's/\(tmpfs   defaults\)/\1,noexec,nodev,nosuid/' /etc/fstab
mount -o remount,noexec,nodev,nosuid /dev/shm

# 1.7.1.2 Informational message of the day issue
grep -v 'Kernel \r on an \m' /etc/issue > /etc/issue.new
mv /etc/issue.new /etc/issue
echo 'Authorized uses only. All activity may be monitored and reported.' >> /etc/issue
cp /etc/issue /etc/issue.net

# 3.4.3 etc hosts deny 
echo "ALL: ALL" >> /etc/hosts.deny

# 1.4.2 Auth needed for single user mode
sed -i 's/\(SINGLE=\/sbin\/\)sushell/\1\sulogin/' /etc/sysconfig/init
