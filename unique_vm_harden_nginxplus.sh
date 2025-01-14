#!/bin/bash

echo "[PROMPT 1] IS NGINX PLUS INSTALLED FROM CS.NGINX.COM REPO: (OPTIONS: yes/no)"
read INSTALL_TYPE

echo "[PROMPT 2] IS NGINX PLUS CONFIGURED WITH HTTP BLOCK - LAYER7: (OPTIONS: yes/no)"
read HTTP_LAYER7

echo "[PROMPT 3] LAYER7 ONLY - INPUT THE SERVER_NAME OF THE SERVER BLOCK TO HARDEN: (EXAMPLE: a.domain.com)"
read SERVER_NAME

echo "[PROMPT 3] LAYER7 ONLY - INPUT THE NGINX CONFIGURATION FILE CONTAINING THE SERVER BLOCK TO HARDEN: (EXAMPLE: /etc/nginx/nginx.conf)"
read SERVER_NAME_FILE

echo "[PROMPT 4] LAYER7 ONLY - INPUT THE SSL CERTIFICATE AND KEY DIRECTORY: (EXAMPLE: /etc/ssl)"
read SSL_CERT_KEY_DIRECTORY


echo "============================== SUMMARY OF YOUR PROMPTS =============================="
echo "[PROMPT 1] is: $INSTALL_TYPE"
echo "[PROMPT 2] is: $HTTP_LAYER7"
echo "[PROMPT 3] is: $SERVER_NAME"
echo "[PROMPT 4] is: $SERVER_NAME_FILE"
echo "[PROMPT 5] is: $SSL_CERT_KEY_DIRECTORY"
echo "============================== PLEASE WAIT... =============================="

nginx -v
echo "============================== 1.1.1 unique_vm_harden_nginxplus =============================="

nginx -v
echo "============================== 1.1.2 unique_vm_harden_nginxplus =============================="

if [ "$INSTALL_TYPE" == "yes" ]; then

dnf repolist -v nginx-plus
echo "============================== 1.2.1 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR BINARY INSTALLATION"
echo "============================== 1.2.1 unique_vm_harden_nginxplus =============================="

fi

nginx -v
echo "============================== 1.2.2 unique_vm_harden_nginxplus =============================="

nginx -V
echo "============================== 2.1.1 unique_vm_harden_nginxplus =============================="

nginx -V 2>&1 | grep http_dav_module # not recommended to remove
echo "============================== 2.1.2 unique_vm_harden_nginxplus =============================="

nginx -V 2>&1 | grep -E '(http_gzip_module|http_gzip_static_module)' # not recommended to remove
echo "============================== 2.1.3 unique_vm_harden_nginxplus =============================="

egrep -i '^\s*autoindex\s+' /etc/nginx/nginx.conf
egrep -i '^\s*autoindex\s+' /etc/nginx/conf.d/*
echo "============================== 2.1.4 unique_vm_harden_nginxplus =============================="

grep -Pi -- '^\h*user\h+[^;\n\r]+\h*;.*$' /etc/nginx/nginx.conf
sudo -l -U nginx
groups nginx
echo "============================== 2.2.1 unique_vm_harden_nginxplus =============================="

sudo passwd -S "$(awk '$1~/^\s*user\s*$/ {print $2}' /etc/nginx/nginx.conf | sed -r 's/;.*//g')"
echo "============================== 2.2.2 unique_vm_harden_nginxplus =============================="

grep '^nginx:' /etc/passwd
echo "/sbin/nologin = non-interactive user, invalid shell"
echo "============================== 2.2.3 unique_vm_harden_nginxplus =============================="

ls -la /etc/nginx
echo "============================== 2.3.1 unique_vm_harden_nginxplus =============================="

find /etc/nginx -type f -exec stat -Lc "%n %a" {} +
echo "============================== 2.3.2 unique_vm_harden_nginxplus =============================="

stat -L -c "%U:%G" /var/run/nginx.pid && stat -L -c "%a" /var/run/nginx.pid
echo "============================== 2.3.3 unique_vm_harden_nginxplus =============================="

if [ "$HTTP_LAYER7" == "yes" ]; then

grep working_directory /etc/nginx/nginx.conf
echo "============================== 2.3.4 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 2.3.4 unique_vm_harden_nginxplus =============================="

fi

grep -ir "listen[^;]*;" /etc/nginx
echo "============================== 2.4.1 unique_vm_harden_nginxplus =============================="

if [ "$HTTP_LAYER7" == "yes" ]; then

curl -k -v https://127.0.0.1 -H 'Host: invalid.host.com'
grep -ir "server_name*" /etc/nginx
echo "============================== 2.4.2 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 2.4.2 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "keepalive_timeout*" /etc/nginx
echo "============================== 2.4.3 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 2.4.3 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "send_timeout*" /etc/nginx
echo "============================== 2.4.4 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 2.4.4 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "server_tokens*" /etc/nginx
echo "============================== 2.5.1 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 2.5.1 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#nginx##" /usr/share/nginx/html/index.html
sudo sed -E -i "s#nginx##" /usr/share/nginx/html/50x.html
echo "============================== 2.5.2 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 2.5.2 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        location \~ \/\\\. \{ deny all; return 404; \}#" $SERVER_NAME_FILE
echo "============================== 2.5.3 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 2.5.3 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        proxy_hide_header X-Powered-By;#" $SERVER_NAME_FILE
sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        proxy_hide_header Server;#" $SERVER_NAME_FILE
echo "============================== 2.5.4 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 2.5.4 unique_vm_harden_nginxplus =============================="

fi

grep -ir "log_format*" /etc/nginx
echo "============================== 3.1 unique_vm_harden_nginxplus =============================="

grep -ir "access_log*" /etc/nginx
echo "============================== 3.2 unique_vm_harden_nginxplus =============================="

grep -ir "error_log*" /etc/nginx
echo "============================== 3.3 unique_vm_harden_nginxplus =============================="

cat /etc/logrotate.d/nginx
echo "============================== 3.4 unique_vm_harden_nginxplus =============================="

grep -ir "error_log syslog*" /etc/nginx
echo "============================== 3.5 unique_vm_harden_nginxplus =============================="

grep -ir "access_log syslog*" /etc/nginx
echo "============================== 3.6 unique_vm_harden_nginxplus =============================="

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        proxy_set_header X-Real-IP \$remote_addr;#" $SERVER_NAME_FILE
sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;#" $SERVER_NAME_FILE
echo "============================== 3.7 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 3.7 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "listen 80;" /etc/nginx
echo "============================== 4.1.1 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.1 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "ssl_certificate*" /etc/nginx
grep -ir "ssl_certificate_key*" /etc/nginx
echo "============================== 4.1.2 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.2 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

ls -la $SSL_CERT_KEY_DIRECTORY
echo "============================== 4.1.3 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.3 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "ssl_protocol*" /etc/nginx
grep -ir "proxy_ssl_protocols*" /etc/nginx
echo "============================== 4.1.4 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.4 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "ssl_ciphers*" /etc/nginx
grep -ir "proxy_ssl_ciphers*" /etc/nginx
echo "============================== 4.1.5 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.5 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "ssl_dhparam*" /etc/nginx
echo "============================== 4.1.6 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.6 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "ssl_stapling*" /etc/nginx
echo "============================== 4.1.7 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.7 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        add_header Strict-Transport-Security \"max-age=15768000;\" always;#" $SERVER_NAME_FILE
echo "============================== 4.1.8 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.8 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "proxy_ssl_certificate*" /etc/nginx
echo "============================== 4.1.9 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.9 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "proxy_ssl_trusted_certificate*" /etc/nginx
grep -ir "proxy_ssl_verify*" /etc/nginx
echo "============================== 4.1.10 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.10 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

echo "Preloading should only be done with careful consideration!"
echo "============================== 4.1.11 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.11 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        ssl_session_tickets off;#" $SERVER_NAME_FILE
echo "============================== 4.1.12 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.12 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

echo "Legacy user agents may not be able to connect to a server using HTTP/2.0"
echo "============================== 4.1.13 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.13 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "ssl_ciphers*" /etc/nginx
grep -ir "proxy_ssl_ciphers*" /etc/nginx
echo "============================== 4.1.14 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 4.1.14 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "allow*" /etc/nginx
grep -ir "deny all*" /etc/nginx
echo "============================== 5.1.1 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.1.1 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n        \}#" $SERVER_NAME_FILE
sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n            return 444;#" $SERVER_NAME_FILE
sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        if (\$request_method \!\~ \^(GET|HEAD|POST)\$) \{#" $SERVER_NAME_FILE
echo "============================== 5.1.2 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.1.2 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "client_body_timeout*" /etc/nginx
grep -ir "client_header_timeout all*" /etc/nginx
echo "============================== 5.2.1 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.2.1 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "client_max_body_size*" /etc/nginx
echo "============================== 5.2.2 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.2.2 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "large_client_header_buffers*" /etc/nginx
echo "============================== 5.2.3 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.2.3 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "limit_conn*" /etc/nginx
echo "============================== 5.2.4 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.2.4 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

grep -ir "limit_req*" /etc/nginx
echo "============================== 5.2.5 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.2.5 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        add_header X-Frame-Options \"SAMEORIGIN\" always;#" $SERVER_NAME_FILE
echo "============================== 5.3.1 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.3.1 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        add_header X-Content-Type-Options \"nosniff\" always;#" $SERVER_NAME_FILE
echo "============================== 5.3.2 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.3.2 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        add_header Content-Security-Policy \"default-src \'self\'\" always;#" $SERVER_NAME_FILE
echo "============================== 5.3.3 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.3.3 unique_vm_harden_nginxplus =============================="

fi

if [ "$HTTP_LAYER7" == "yes" ]; then

sudo sed -E -i "s#server_name $SERVER_NAME;#server_name $SERVER_NAME;\n\n        add_header Referrer-Policy \"no-referrer\";#" $SERVER_NAME_FILE
echo "============================== 5.3.4 unique_vm_harden_nginxplus =============================="

else

echo "NOT APPLICABLE FOR LAYER4 CONFIGURATION"
echo "============================== 5.3.4 unique_vm_harden_nginxplus =============================="

fi


