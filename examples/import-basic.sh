#!/bin/bash
# Basic firewall-cmd commands for testing bash import
# Expected: all commands parsed successfully, 2 skipped (shebang + this comment)

# Zone: public — services, ports, protocols
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --permanent --zone=public --add-service=ssh
firewall-cmd --permanent --zone=public --add-port=8080/tcp
firewall-cmd --permanent --zone=public --add-port=8443/tcp
firewall-cmd --permanent --zone=public --add-port=53/udp
firewall-cmd --permanent --zone=public --add-protocol=icmp

# Zone: public — sources, interfaces, target
firewall-cmd --permanent --zone=public --add-source=10.0.0.0/8
firewall-cmd --permanent --zone=public --add-source=192.168.1.0/24
firewall-cmd --permanent --zone=public --add-interface=eth0
firewall-cmd --permanent --zone=public --set-target=DROP

# Zone: public — forward, masquerade
firewall-cmd --permanent --zone=public --add-forward
firewall-cmd --permanent --zone=public --add-masquerade

# Zone: public — forward ports
firewall-cmd --permanent --zone=public --add-forward-port=port=80:proto=tcp:toport=8080
firewall-cmd --permanent --zone=public --add-forward-port=port=443:proto=tcp:toport=8443:toaddr=10.0.0.5

# Zone: public — source ports
firewall-cmd --permanent --zone=public --add-source-port=1024/tcp

# Zone: public — ICMP blocks
firewall-cmd --permanent --zone=public --add-icmp-block=echo-reply
firewall-cmd --permanent --zone=public --add-icmp-block=timestamp-request
firewall-cmd --permanent --zone=public --add-icmp-block-inversion

# Zone: trusted — separate zone
firewall-cmd --permanent --zone=trusted --add-source=172.16.0.0/12
firewall-cmd --permanent --zone=trusted --add-service=dns

# Rich rules
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="10.0.0.1" service name="ssh" accept'
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="3306" protocol="tcp" accept'
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" drop'
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" service name="http" log prefix="HTTP_ACCESS" level="info" accept'
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="172.16.0.0/12" port port="5432" protocol="tcp" reject type="icmp-port-unreachable"'

# Direct rules
firewall-cmd --permanent --direct --add-chain ipv4 filter DOCKER-USER
firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 -j RETURN -s 172.16.0.0/12
firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 10 -j DROP
firewall-cmd --permanent --direct --add-passthrough ipv4 -t nat -A POSTROUTING -o eth0 -j MASQUERADE

firewall-cmd --reload
