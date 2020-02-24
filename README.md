# my-webserver-hardening

MY PUBLIC GUIDE TO HARDEN A WEBSERVEr
What I needed to harden my webserver


# User Policies

## <u>PAM</u>

### <u>Password</u>

This enforces authentication policy such as password length, characters etc...



First we need to make sure that `libpam-cracklib` is installed 

```bash
sudo apt install --force-yes -y libpam-cracklib
```

Next we edit `/etc/pam.d/common-password` 

```bash
password requisite pam_cracklib.so retry=3 minlen=8 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1

# Various options retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1

password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass sha512 minlen=8 remember=5p

# Not used before use as last resort
password requisite pam_pwhistory.so use_authtok remember=5 enforce_for_root

# Remove any mention of nullok or nullok_secure 
sed -i 's/nullok//g' 
```



Then we can install `fail2ban` which is 

> an intrusion prevention software framework that protects computer servers from brute-force attacks

```bash
sudo apt install --force-yes -y fail2ban
```



### <u>Login</u>

Edit `/etc/login.defs`

```bash
PASS_MAX_DAYS             90
PASS_MIN_DAYS             10
PASS_WARN_AGE              7
FAILLOG_ENAB             yes
LOG_UNKFAIL_ENAB         yes
LOG_OK_LOGINS            yes
SYSLOG_SU_ENAB           yes 
SYSLOG_SG_ENAB           yes
LOGIN_RETRIES	           5
ENCRYPT_METHOD        SHA512
SU_NAME	                  su
MD5_CRYPT_ENAB           yes
LOGIN_TIMEOUT		      60

UMASK					077
```



Edit `/root/.bashrc`

```bash
umask 077 # Uncomment this line and edit
```



Edit `/etc/init.d/rc`

```bash
umask 027 # Edit the line
```



You can also use `chage`

```bash
chage -m 10 <user>
chage -M 90 <user>
chage -W 7  <user>
```



Edit `/etc/pam.d/login` 

```bash
auth       optional   pam_faildelay.so  delay=10000000 # 10 seconds
```



### <u>Account Policy</u>

This changes how many incorrect logins you're allowed and how long you have to wait. This is done by editing `/etc/pam.d/common-auth` and you have to just add

to the end of the file

```bash
echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800 audit even_deny_root_account silent" >> /etc/pam.d/common-auth

# Remove any mention of nullok or nullok_secure
sed -i 's/nullok//g'
```



### <u>Su</u>

You don't want any sudo to be able to use su and login as root

To disable this, you can either:



Uncomment the line with `pam_wheel.so` in 

```bash
/etc/pam.d/su
```

<u>Or</u>

Uncomment `SU_WHEEL_ONLY` in 

```
/etc/logins.def
```


# Services

## Securing Services

### <u>Securing SSH</u>

We don't want anyone to be able to become root from ssh. We can just use some trusty regex and `sed` to change this in `/etc/ssh/sshd_config`

```bash
sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
```



All these settings can be changed in a similar manner

```bash
Port 222 # Only change this if needed

Protocol 2
PermitRootLogin no
PermitEmptyPasswords no

X11Forwarding no
AllowTcpForwarding no

UsePAM yes 
PasswordAuthentication yes 
HostBasedAuthentication no
StrictModes yes

UsePrivilegeSeparation yes
PrintLastLog no
PermitUserEnvironment no

LogLevel INFO
MaxAuthTries 4
IgnoreRhosts yes # Force user entering password

Ciphers aes128-ctr,aes192-ctr,aes256-ctr
ClientAliveInterval 300
ClientAliveCountMax 0
Banner /etc/issue.net # Change this file to remove fingerprinting

# Other

AllowGroups wheel admin
AllowUsers alex ref me@somewhere 
DenyUser bad_user1 bad_user_2
```



Edit `/etc/issue.net`

```bash
echo "Hello" > /etc/issue.net	
```



Make sure to restart SSH

```bash
sudo service ssh restart
```

It may also be called `sshd` or `openssh`. Make sure to use the package name.



More info at: [http://bookofzeus.com/harden-ubuntu/hardening/ssh/](http://bookofzeus.com/harden-ubuntu/hardening/ssh/)

### <u>Securing Samba</u>

Edit or add the lines `/etc/samba/smb.conf`

```stylus
restrict anonymous = 2
encrypt passwords = True
encrypt passwords = yes
read only = Yes
ntlm auth = no
obey pam restrictions = yes
server signing = mandatory
smb encrypt = mandatory
min protocol = SMB2
protocol = SMB2
guest ok = no
max log size = 24
```



### <u>Securing FTP</u>

Config locations:

```bash
# FTPd
/etc/ftpd.conf

#VsFTPd
/etc/vsftpd/vsftpd.conf

# ProFTPd
/etc/proftpd.conf 
/usr/local/proftpd.conf
```



Change anonymous to off - check by trying to login to `localhost`

```bash
$ ftp localhost

USER: anonymous
PASSWORD: <literally anything>
```



Restart by using 

```bash
service <proftpd/ftpd> restart
```



#### VsFTPd

```bash
/etc/vsftpd/vsftpd.conf 

# Jail users to home directory (user will need a home dir to exist)
chroot_local_user=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
allow_writeable_chroot=YES # Only enable if you want files to be editable

# Allow or deny users
userlist_enable=YES                  
userlist_file=/etc/vsftpd.userlist    
userlist_deny=NO  

# General config
anonymous_enable=NO      # disable  anonymous login
local_enable=YES		 # permit local logins
write_enable=YES		 # enable FTP commands which change the filesystem
local_umask=022		     # value of umask for file creation for local users
dirmessage_enable=YES	 # enable showing of messages when users first enter a new directory
xferlog_enable=YES		 # a log file will be maintained detailing uploads and downloads
connect_from_port_20=YES # use port 20 (ftp-data) on the server machine for PORT style connections
xferlog_std_format=YES   # keep standard log file format
listen=NO   			 # prevent vsftpd from running in standalone mode
listen_ipv6=YES		     # vsftpd will listen on an IPv6 socket instead of an IPv4 one
pam_service_name=vsftpd  # name of the PAM service vsftpd will use
userlist_enable=YES  	 # enable vsftpd to load a list of usernames
tcp_wrappers=YES  		 # turn on tcp wrappers

ascii_upload_enable=NO
ascii_download_enable=NO
```



#### PureFTPd

```bash
echo "yes" >> /etc/pure-ftpd/conf/NoAnonymous
echo "yes" >> /etc/pure-ftpd/conf/ChrootEveryone
echo "yes" >> /etc/pure-ftpd/conf/IPV4Only
echo "yes" >> /etc/pure-ftpd/conf/ProhibitDotFilesWrite
echo "2" > /etc/pure-ftpd/conf/TLS
echo 2 |  tee /etc/pure-ftpd/conf/TLS
echo 1 |  tee /etc/pure-ftpd/conf/NoAnonymous
```



#### ProFTPd

Edit or add the lines in `/etc/proftpd/proftpd.conf`

```stylus
DenyFilter \*.*/
DelayEngine on
UseLastLog on 
ServerIndent off
IdentLookups off
TLSEngine on
TLSProtocol SSLv23
TLSRequired on 
UseReverseDNS on
```



##### After applying changes

```bash
systemctl restart <service>
service <service> restart
```



### <u>Securing MySql</u>

###### Secure Installation

```bash
apt install mysql-server
sudo mysql_secure_installation
```



Config file: `/etc/mysql/my.cnf`

```bash
[mysqld]
local-infile=0               # Stop mysql reading files from local file system
skip-show-database           # Lowers database privelages
bind-address=127.0.0.1       # Disable remote access
symbolic-links=0             # Disables symbolic links
default_password_lifetime=90 # Set password expiration

[mysqladmin]                 # Sets root account password
user=root
password=<PASSWORD>
# Packet Restrictions
key_buffer_size=16M
max_allowed_packet=16M
```



##### Change/Read root password

```bash
service mysql stop
mysqld_safe --skip-grant-tables &

#Now you can go into mysql as root
mysql -u root

UPDATE mysql.user SET Password=PASSWORD('NEW-PASSWORD') WHERE User='root';
#or
SELECT * from mysql.user;
#Now crack the hash
```



##### Enable SSL

```bash
mkdir ~/cert && cd ~/cert

openssl genrsa 2048 > ca-key.pem
openssl req -sha1 -new -x509 -nodes -key ca-key.pem -subj "/CN=certificate-authority" > ca-cert.pem

openssl req -sha1 -newkey rsa:2048 -nodes -keyout server-key.pem -subj "/CN=mysql-server" > server-req.pem
openssl x509 -sha1 -req -in server-req.pem  -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-cert.pem
openssl rsa -in server-key.pem -out server-key.pem

openssl req -sha1 -newkey rsa:2048 -nodes -keyout client-key.pem -subj "/CN=mysql-client" > client-req.pem
openssl x509 -sha1 -req -in client-req.pem -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > client-cert.pem
openssl rsa -in client-key.pem -out client-key.pem

mkdir -p /etc/mysql/ssl
cp ca-cert.pem server-cert.pem server-key.pem /etc/mysql/ssl
chown -R mysql.mysql /etc/mysql/ssl
chmod -R 700 /etc/mysql/ssl
```



Now edit `/etc/mysql/my.cnf`

```bash
[mysqld]
ssl-ca=   /etc/mysql/ssl/ca-cert.pem
ssl-cert= /etc/mysql/ssl/server-cert.pem
ssl-key=  /etc/mysql/ssl/server-key.pem
```



Restart and check if it worked

```bash
$ /etc/init.d/mysql restart
$ mysql -u root -e "SHOW GLOBAL VARIABLES LIKE 'have_%ssl';"
+---------------+-------+
| Variable_name | Value |
+---------------+-------+
| have_openssl  | YES   |
| have_ssl      | YES   |
+---------------+-------+

```



### <u>Securing Apache</u>

Just try and go to 

```bash
http://localhosts/	
```

If this exists, you can go to `/var/www/html` to edit files etc.



###### <u>Check these things</u>

```bash
Not running as root user
Apache account has invalid shell (/etc/passwd)

chown -R root:root /etc/apache2
chown -R root:root /etc/apache
```



###### Disable unnecessary modules

List modules:

```
apache2 -l
grep -r LoadModule /etc/apache2/mods-enabled/*
```



Enable/Disable modules:

```bash
a2enmod userdir
a2enmod headers
a2dismod imap
a2dismod include
a2dismod info
a2dismod userdir
a2dismod autoindex
```



###### Mod_security

```bash
apt install mod_security
service httpd restart
```



###### Security Configuration

Edit `/etc/apache2/conf-available/security.conf` add or edit the following lines

```bash
# Enable HTTPOnly and Secure Flags
Header edit Set-Cookie ^(.*)\$ \$1;HttpOnly;Secure

# Clickjacking Attack Protection
Header always append X-Frame-Options SAMEORIGIN

# XSS Protection
Header set X-XSS-Protection "1; mode=block"

# Enforce secure connections to the server
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# MIME sniffing Protection
Header set X-Content-Type-Options: "nosniff"

# Prevent Cross-site scripting and injections
Header set Content-Security-Policy "default-src 'self';"
```



###### Regular configuration

File: `/etc/apache2/apache2.conf`

**Add the lines inside within a previous existing root node if possible**

```bash
HostnameLookups Off
LogLevel warn
ServerTokens Prod
ServerSignature Off
Options all -Indexes
Header unset ETag
Header always unset X-Powered-By
FileETag None
TraceEnable off
Timeout 60
RewriteEngine On

# Secure /
<Directory />
  Options -Indexes
  AllowOverride None
  Order Deny,Allow
  Options None
  Deny from all
</Directory>
 
# Secure /var/www/html

<Directory />
  Options -Indexes -Includes
  AllowOverride None
  Order Allow,Deny
  Deny from All
</Directory>

# Disable old protocol (HTTP 1.0)
RewriteEngine On
RewriteCond %{THE_REQUEST} !HTTP/1\.1$
RewriteRule .* - [F]

# Disable SSI (Server Side Inclusion)
# Search for Directory and add Includes in Options directive:
<Directory /path/to/htdocs>
  Options -Indexes -Includes
  Order allow,deny
  Allow from all
</Directory>

# Disable CGI execution
# Similar to SSI, you can disable CGI Execution in the "apache2.conf" by adding the "-ExecCGI" option.
<Directory /path/to/htdocs>
  Options -Indexes -Includes -ExecCGI
  Order allow,deny
  Allow from all
</Directory>
```



Then restart apache

```bash
sudo service apache2 restart
```



See more at: [http://bookofzeus.com/harden-ubuntu/hardening/apache/](http://bookofzeus.com/harden-ubuntu/hardening/apache/)



### <u>Securing Nginx</u>



Remove default page

```bash
echo > /var/www/index.html
```



Edit or add these lines in `/etc/nginx/nginx.conf`

```bash
# Hide nginx version
server_tokens off;

# Remove etags
etag off;

# Strong cipher suites
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;

# Set ssl session timeout
ssl_prefer_server_ciphers on;
ssl_session_timeout 5m;
```



Edit or add these lines in `/etc/nginx/sites-available/default`

Inside the `server{...}`	

```bash
# Enable HttpOnly and Secure flags
proxy_cookie_path / "/; HTTPOnly;   Secure";		
# Clickjacking Attack Protection
add_header X-Frame-Options DENY;
# XSS Protection
add_header X-XSS-Protection "1; mode=block";
# Enforce secure connections to the server
add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";
# MIME sniffing Protection
add_header X-Content-Type-Options nosniff;
# Prevent Cross-site scripting and injections
add_header Content-Security-Policy \"default-src 'self';\";
# Set X-Robots-Tag
add_header X-Robots-Tag none;
```



### <u>Securing PHP</u>

```bash
ufw allow php
```



##### php.ini

Find the file by doing 

```bash
php -i | grep "php.ini"
```



Edit or add the following lines

```bash
# Safe mode
safe_mode=On
safe_mode_gid=On

# Disable Global variables
register_globals=off

# Disable tracking, HTML, and display errors
track_errors=Off
html_errors=Off
display_errors=Off
expose_php=Off
track_errors=Off
html_errors=Off
display_errors=Off
mail.add_x_header=Off

# Disable Remote File Includes
allow_url_fopen=Off
allow_url_include=Off

# Restrict File Uploads
file_uploads=Off

# Control POST/Upload size
post_max_size=1K
upload_max_filesize=2M

# Protect sessions
session.cookie_httponly=1

# General
magic_quotes_gpc=Off
session.use_strict_mode=On

disable_functions=exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec

max_execution_time=30
max_input_time=30
open_basedir="/home/user/public_html" # -> correct html base dir
memory_limit=40M
```



##### Suhosin

Install

```bash
apt install php5-suhosin -y
```



Edit or add the lines in `/etc/php5/conf.d/suhosin.ini`

```bash
extension=suhosin.so
suhosin.session.encrypt=Off
suhosin.log.syslog=511
suhosin.executor.include.max_traversal=4
suhosin.executor.disable_eval=On
suhosin.executor.disable_emodifier=On
suhosin.mail.protect=2
suhosin.sql.bailout_on_error=On
```



### <u>Securing DNS / Hosts</u>



#### <u>Bind9</u>

If `bind9` exists

Open a Terminal and enter the following :

```bash
sudo vi /etc/bind/named.conf.options
```

Add the following to the **Options** section :

```bash
recursion no;
version "Not Disclosed";
```

Restart BIND DNS server. Open a Terminal and enter the following :

```bash
sudo service bind9 restart
```



(Look in more info for links)




# Sysctl

### <u>Network</u>



You need to set all of these values	

```bash
# IPv4 TIME-WAIT assassination protection
net.ipv4.tcp_rfc1337=1 

# IP Spoofing protection, Source route verification  
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts=1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all=1

# Log Martians
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_ignore_bogus_error_responses=1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0

net.ipv6.conf.all.accept_source_route=0 
net.ipv6.conf.default.accept_source_route=0

# Block SYN attacks
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=4 # Try values 1-5


# Ignore ICMP redirects
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0

net.ipv6.conf.all.send_redirects=0 # ignore ?
net.ipv6.conf.default.send_redirects=0 # ignore ?
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0 
net.ipv6.conf.all.secure_redirects=0 # ignore ?
net.ipv6.conf.default.secure_redirects=0 # ignore ?

# Note disabling ipv6 means you dont need the majority of the ipv6 settings

# General options
net.ipv6.conf.default.router_solicitations=0
net.ipv6.conf.default.accept_ra_rtr_pref=0
net.ipv6.conf.default.accept_ra_pinfo=0
net.ipv6.conf.default.accept_ra_defrtr=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.dad_transmits=0
net.ipv6.conf.default.max_addresses=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1

```

### <u>Sysctl</u>

`/etc/sysctl.conf`

```bash
kernel.dmesg_restrict=1 		
fs.suid_dumpable=0 # Core dumps 
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.sysrq = 0
kernel.maps_protect=1
kernel.core_uses_pid=1
kernel.shmmax = 68719476736
kernel.shmall = 4294967296

kernel.exec_shield=1 # Or 
echo "kernel.exec-shield = 1" > /etc/sysctl.d/50-exec-shield.conf

kernel.panic=10
kernel.kptr_restrict=2
vm.panic_on_oom=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
kernel.randomize_va_space=2 		# ASLR; 2 = full; 1 = semi; 0 = none
kernel.unprivileged_userns_clone=0 	# 
kernel.ctrl-alt-del=0 				# CTRL-ALT-DEL disable
```
These can all be found in the file `/etc/sysctl.conf`



To reload `sysctl` with the latest changes, enter:

```bash
# Idk difference try both lol
sudo sysctl --system 
sudo sysctl -p 
# Better to write to file /etc/sysctl.conf
```



### <u>File permissions</u>

Set these file permissions correctly

```bash
chattr -i /etc/passwd          
chattr -i /etc/group           
chattr -i /etc/shadow  		   
chattr -i /etc/ssh/sshd_config 
chattr -i /etc/lightdm/lightdm.conf
chattr -i /etc/profile
chattr -i /etc/bash.bashrc
chattr -i /etc/login.defs
chattr -i /etc/pam.d/common-auth
chattr -i /etc/pam.d/common-password
chattr -i /etc/host.conf
chattr -i /etc/hosts.deny
chattr -i /etc/hosts.allow
chattr -i /etc/hosts
chattr -i /etc/resolv.conf
chattr -i /etc/default/grub  		
chattr -i /etc/grub.d/40_custom  	
chattr -i /etc/ers
chattr -i ~/.mozilla/firefox/*.default/prefs.js
chattr -i /etc/sysctl.conf
chattr -i /etc/apt/sources.list
chattr -i /etc/lightdm/lightdm.conf.d/50-myconfig.conf

chown root:root /etc/fstab   
chmod 644 /etc/fstab  		 
chown root:root /etc/group   
chmod 644 /etc/group  		 
chown root:root /etc/shadow  
chmod 400 /etc/shadow  		 
chown root:root /etc/apache2 
chmod 755 /etc/apache2  	 

chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinetd.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
chmod 440 /etc/ers
chmod 640 /etc/shadow  			
chmod 600 /boot/grub/grub.cfg   
chmod 600 /etc/ssh/sshd_config  
chmod 600 /etc/gshadow-        
chmod 600 /etc/group-           
chmod 600 /etc/passwd-          

chown root:root /etc/ssh/sshd_config 
chown root:root /etc/passwd-         
chown root:root /etc/group-          
chown root:root /etc/shadow          
chown root:root /etc/securetty
chown root:root /boot/grub/grub.cfg  

chmod og-rwx /boot/grub/grub.cfg  	
chown root:shadow /etc/shadow-  	
chmod o-rwx,g-rw /etc/shadow-  		
chown root:shadow /etc/gshadow-  
chmod o-rwx,g-rw /etc/gshadow-
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chmod -R g-wx,o-rwx /var/log/*
```



# Access Control

## <u>AppArmor</u>

Run 

```bash
aa-enforce /etc/apparmor.d/*

aa-enforce /etc/apparmor.d/usr.bin.Firefox # Firefox specific
```

