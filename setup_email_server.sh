#!/bin/bash




set -e

# Ensure the script is run by 'root' user
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

# Validate required environment variables
if [[ -z "$MYSQL_ROOT_PASSWORD" || -z "$MYSQL_POSTFIX_PASSWORD" ]]; then
  echo "Error: Required environment variables (MYSQL_ROOT_PASSWORD, MYSQL_POSTFIX_PASSWORD) are not set."
  exit 1
fi

# Check for the domain argument
if [ -z "$1" ]; then
  echo "Usage: $0 <DOMAIN>"
  exit 1
fi


# Variables
DOMAIN=$1
EMAIL="admin@$DOMAIN"
SSL_CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
VMAIL_USER="vmail"
VMAIL_GROUP="vmail"
VMAIL_UID=5000
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
MYSQL_POSTFIX_PASSWORD=${MYSQL_POSTFIX_PASSWORD}
POSTFIX_CONF_DIR="/etc/postfix"
DOVECOT_CONF_DIR="/etc/dovecot"
ROUNDCUBE_DIR="/var/www/roundcube"
CRON_FILE="/etc/cron.d/auto_update"



# Disable Apache2 if installed and running
if systemctl is-active --quiet apache2; then
  systemctl stop apache2
  systemctl disable apache2
fi

# Update and install necessary packages
apt update
apt upgrade -y
apt install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-mysql opendkim opendkim-tools spamassassin spamc clamav clamav-daemon clamav-milter certbot ufw nginx php php-fpm php-mysql mariadb-server roundcube roundcube-mysql roundcube-plugins unzip arj bzip2 cabextract cpio file gzip lha lzop nomarch p7zip pax rar rpm unrar unzip zip zoo

# Ensure necessary directories exist
mkdir -p /etc/postfix
mkdir -p /etc/dovecot
mkdir -p /var/www/roundcube
mkdir -p /var/mail/vmail
mkdir -p /etc/opendkim
mkdir -p /etc/opendkim/keys
mkdir -p /var/spool/postfix/spamassassin
mkdir -p /var/mail/vmail/sieve/global

# Make sure appropriate ownership is assigned
chown -R $VMAIL_USER:$VMAIL_GROUP /var/mail/vmail
chown -R www-data:www-data /var/www/roundcube
chown -R opendkim:opendkim /etc/opendkim
chown -R clamav:clamav /var/spool/postfix/spamassassin
chown -R spamd:spamd /var/spool/postfix/spamassassin

# Create virtual mail user and directories
groupadd -g $VMAIL_UID $VMAIL_GROUP || echo "Group $VMAIL_GROUP already exists."
useradd -m -d /var/mail/vmail -s /usr/sbin/nologin -u $VMAIL_UID -g $VMAIL_GROUP $VMAIL_USER || echo "User $VMAIL_USER already exists."

# Set up Let's Encrypt SSL Certificates
certbot certonly --standalone -d mail.$DOMAIN --non-interactive --agree-tos --email $EMAIL

# MariaDB setup for Postfix and Roundcube
mysql -uroot -p"$MYSQL_ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS postfix;
CREATE USER IF NOT EXISTS 'postfix'@'localhost' IDENTIFIED BY '$MYSQL_POSTFIX_PASSWORD';
GRANT ALL PRIVILEGES ON postfix.* TO 'postfix'@'localhost';
FLUSH PRIVILEGES;

CREATE DATABASE IF NOT EXISTS roundcube;
CREATE USER IF NOT EXISTS 'roundcube'@'localhost' IDENTIFIED BY '$MYSQL_POSTFIX_PASSWORD';
GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure Postfix
postconf -e "myhostname = mail.$DOMAIN"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = /etc/mailname"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
postconf -e "home_mailbox = Maildir/"
postconf -e "smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)"
postconf -e "biff = no"
postconf -e "append_dot_mydomain = no"
postconf -e "readme_directory = no"
postconf -e "compatibility_level = 2"
postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"
postconf -e "smtpd_tls_cert_file = $SSL_CERT_DIR/fullchain.pem"
postconf -e "smtpd_tls_key_file = $SSL_CERT_DIR/privkey.pem"
postconf -e "smtpd_use_tls=yes"
postconf -e "smtp_use_tls=yes"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache"
postconf -e "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache"
postconf -e "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination"
postconf -e "myhostname = mail.$DOMAIN"
postconf -e "relayhost ="
postconf -e "myorigin = /etc/mailname"
postconf -e "mydestination = $DOMAIN, localhost.$DOMAIN, localhost"
postconf -e "sender_bcc_maps = hash:/etc/postfix/bcc"
postconf -e "recipient_bcc_maps = hash:/etc/postfix/bcc"
postconf -e "dovecot_destination_recipient_limit = 1"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_note_starttls_offer = yes"

echo "$DOMAIN" > /etc/mailname
echo "root@mail.$DOMAIN root" >> /etc/aliases
newaliases

# Configure Dovecot
cat <<EOF >/etc/dovecot/dovecot.conf
disable_plaintext_auth = yes
ssl = required
ssl_cert = <$SSL_CERT_DIR/fullchain.pem
ssl_key = <$SSL_CERT_DIR/privkey.pem
mail_location = maildir:/var/mail/vmail/%d/%n/mail
namespace inbox {
  inbox = yes
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}
protocols = imap
auth_mechanisms = plain login
mail_home = /var/mail/vmail/%d/%n
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = static
  args = uid=$VMAIL_UID gid=$VMAIL_UID home=/var/mail/vmail/%d/%n
}
plugin {
  sieve = /var/mail/vmail/sieve/%d/%n
  sieve_dir = /var/mail/vmail/sieve/%d/%n/sievedir
}
EOF

cat <<EOF >/etc/dovecot/dovecot-sql.conf.ext
driver = mysql
connect = host=localhost dbname=postfix user=postfix password=$MYSQL_POSTFIX_PASSWORD
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';
user_query = SELECT email as user, '/var/mail/vmail/%d/%n' as home, 'maildir:/var/mail/vmail/%d/%n' as mail FROM virtual_users WHERE email='%u';
EOF

# Set up SpamAssassin
echo 'ENABLED=1' > /etc/default/spamassassin
systemctl restart spamassassin
systemctl enable spamassassin

# Set up ClamAV
cat <<EOF >/etc/clamav/clamd.conf
LogFile /var/log/clamav/clamav.log
LogFileMaxSize 2M
LogTime yes
PidFile /var/run/clamd.pid
TemporaryDirectory /tmp
DatabaseDirectory /var/lib/clamav
LocalSocket /var/run/clamav/clamd.ctl
FixStaleSocket yes
User $VMAIL_USER
AllowSupplementaryGroups yes
ScanMail yes
ScanArchive yes
ArchiveBlockEncrypted no
MaxDirectoryRecursion 15
FollowDirectorySymlinks yes
FollowFileSymlinks yes
ReadTimeout 180
EOF

systemctl restart clamav-daemon
systemctl enable clamav-daemon

# Configure OpenDKIM
cat <<EOF >/etc/opendkim.conf
Syslog                  yes
UMask                   002
Domain                  $DOMAIN
KeyFile                 /etc/opendkim/keys/${DOMAIN}.private
Selector                mail
Socket                  inet:8891@localhost
PidFile                 /var/run/opendkim/opendkim.pid
Mode                    sv
Canonicalization        relaxed/simple
SignHeaders             From, To, Subject
EOF

cat <<EOF >/etc/default/opendkim
SOCKET="inet:8891@localhost"
EOF

# Generate and configure DKIM keys
opendkim-genkey -D /etc/opendkim/keys/ -d $DOMAIN -s mail
mv /etc/opendkim/keys/mail.private /etc/opendkim/keys/${DOMAIN}.private
chown opendkim:opendkim /etc/opendkim/keys/${DOMAIN}.private
cat /etc/opendkim/keys/mail.txt

# Communicate public key for DNS TXT record setup
echo "Add the following DKIM key record to your DNS:"
cat /etc/opendkim/keys/mail.txt

# Set up Nginx for HTTPS only
cat <<EOF >/etc/nginx/sites-available/roundcube
server {
  listen 80;
  server_name mail.$DOMAIN;
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl http2 default_server;
  server_name mail.$DOMAIN;

  ssl_certificate $SSL_CERT_DIR/fullchain.pem;
  ssl_certificate_key $SSL_CERT_DIR/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AES:RSA+3DES:!ADH:!AECDH:!MD5:!DSS;

  root $ROUNDCUBE_DIR;
  index index.php index.html index.htm;
  autoindex off;

  location / {
    try_files \$uri \$uri/ =404;
  }

  location ~ ^/(README|INSTALL|LICENSE|CHANGELOG|UPGRADING)$ {
        deny all;
    }

  location ~ \.php$ {
    try_files $uri =404;
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/var/run/php/php-fpm.sock;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    fastcgi_intercept_errors on;
  }

  location ~ /\.ht {
    deny all;
  }
}
EOF

ln -s /etc/nginx/sites-available/roundcube /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default

# Basic Sieve Filter Example
cat <<EOF > /var/mail/vmail/sieve/global/default.sieve
require ["fileinto", "imap4flags"];

# Move spam to spam folder
if header :contains "X-Spam-Flag" "YES" {
    fileinto "Spam";
    stop;
}

# Move read mails to another folder
if allof (not flagged "\\Seen") {
    fileinto "Read";
    stop;
}
EOF

sievec /var/mail/vmail/sieve/global/default.sieve
chown -R $VMAIL_USER:$VMAIL_GROUP /var/mail/vmail/sieve/global

# Configure Roundcube
roundcube-db-config <<EOF
mysql
roundcube
roundcube
localhost
$MYSQL_POSTFIX_PASSWORD
EOF

configure-roundcube

# Set up UFW
ufw allow 22
ufw allow 25
ufw allow 143
ufw allow 587
ufw allow 993
ufw allow 'Nginx Full'
ufw enable

# Setup cronjob for automatic updates
cat <<EOF > $CRON_FILE
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root apt update && apt upgrade -y && apt autoremove -y && apt autoclean
EOF

chmod 0644 $CRON_FILE
crontab $CRON_FILE

# Restart and enable necessary services
systemctl restart postfix
systemctl restart dovecot
systemctl restart nginx
systemctl enable postfix
systemctl enable dovecot
systemctl enable nginx

echo "Mail server setup complete!"
