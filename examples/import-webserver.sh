#!/bin/bash
# Real-world scenario: Web server with reverse proxy, database, and management zone
# Simulates a production setup with three zones

# --- Public zone: web traffic ---
firewall-cmd --permanent --zone=public --set-target=DROP
firewall-cmd --permanent --zone=public --add-interface=ens192
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --permanent --zone=public --add-port=8080/tcp
firewall-cmd --permanent --zone=public --add-port=8443/tcp
firewall-cmd --permanent --zone=public --add-forward
firewall-cmd --permanent --zone=public --add-masquerade
firewall-cmd --permanent --zone=public --add-forward-port=port=80:proto=tcp:toport=8080:toaddr=10.10.0.2
firewall-cmd --permanent --zone=public --add-forward-port=port=443:proto=tcp:toport=8443:toaddr=10.10.0.2
firewall-cmd --permanent --zone=public --add-icmp-block=echo-reply
firewall-cmd --permanent --zone=public --add-icmp-block=timestamp-request
firewall-cmd --permanent --zone=public --add-icmp-block=timestamp-reply
firewall-cmd --permanent --zone=public --add-icmp-block-inversion
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" port port="80" protocol="tcp" accept'
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" port port="443" protocol="tcp" accept'
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" service name="http" log prefix="HTTP" level="info" limit value="5/m" accept'

# --- Internal zone: database access from app servers only ---
firewall-cmd --permanent --zone=internal --add-source=10.10.0.0/24
firewall-cmd --permanent --zone=internal --add-source=10.10.1.0/24
firewall-cmd --permanent --zone=internal --add-port=5432/tcp
firewall-cmd --permanent --zone=internal --add-port=6379/tcp
firewall-cmd --permanent --zone=internal --add-port=27017/tcp
firewall-cmd --permanent --zone=internal --add-rich-rule='rule family="ipv4" source address="10.10.0.0/24" port port="5432" protocol="tcp" accept'
firewall-cmd --permanent --zone=internal --add-rich-rule='rule family="ipv4" source address="10.10.1.0/24" port port="6379" protocol="tcp" accept'
firewall-cmd --permanent --zone=internal --add-rich-rule='rule family="ipv4" source address="10.10.0.5" port port="27017" protocol="tcp" accept'

# --- Trusted zone: management / SSH ---
firewall-cmd --permanent --zone=trusted --add-source=10.200.0.0/16
firewall-cmd --permanent --zone=trusted --add-service=ssh
firewall-cmd --permanent --zone=trusted --add-service=cockpit
firewall-cmd --permanent --zone=trusted --add-port=9090/tcp
firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family="ipv4" source address="10.200.0.1" service name="ssh" accept'
firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family="ipv4" source address="10.200.0.0/16" service name="cockpit" accept'

# --- Direct rules: Docker network isolation ---
firewall-cmd --permanent --direct --add-chain ipv4 filter DOCKER-USER
firewall-cmd --permanent --direct --add-chain ipv6 filter DOCKER-USER
firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv6 filter DOCKER-USER 0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 -j RETURN -s 172.16.0.0/12
firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 -j RETURN -s 10.10.0.0/24 -p tcp --dport 80
firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 -j RETURN -s 10.10.0.0/24 -p tcp --dport 443
firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 10 -j DROP
firewall-cmd --permanent --direct --add-rule ipv6 filter DOCKER-USER 10 -j DROP
firewall-cmd --permanent --direct --add-passthrough ipv4 -t nat -A POSTROUTING -o ens192 -j MASQUERADE

firewall-cmd --reload
