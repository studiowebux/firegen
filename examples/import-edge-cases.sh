#!/bin/bash
# Edge cases for bash import testing
# Tests: shell variables (errors), zone-less commands (default public),
# query commands (skipped), reload variants (skipped), sudo prefix

# --- Should be SKIPPED (comments, blank lines) ---

# This is a comment

# --- Should be SKIPPED (reload variants) ---
firewall-cmd --reload
sudo firewall-cmd --reload
firewall-cmd --complete-reload
firewall-cmd --permanent --reload

# --- Should be SKIPPED (non-modifying / query commands) ---
firewall-cmd --state
firewall-cmd --version
firewall-cmd --get-zones
firewall-cmd --get-services
firewall-cmd --get-default-zone
firewall-cmd --get-active-zones
firewall-cmd --get-log-denied
firewall-cmd --list-all
firewall-cmd --list-all-zones
firewall-cmd --list-services
firewall-cmd --list-ports
firewall-cmd --zone=public --list-rich-rules
firewall-cmd --query-service=http
firewall-cmd --query-port=80/tcp
firewall-cmd --runtime-to-permanent
firewall-cmd --check-config

# --- Should ERROR (shell variables) ---
firewall-cmd --permanent --zone=public --add-port=$PORT/tcp
firewall-cmd --permanent --zone=${ZONE} --add-service=http
firewall-cmd --permanent --zone=public --add-source=$(echo 10.0.0.0/8)

# --- Should PARSE into zone "public" (zone-less modifying commands) ---
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-source=10.0.0.0/8
sudo firewall-cmd --permanent --add-service=dns
firewall-cmd --add-service=https
firewall-cmd --permanent --set-target=ACCEPT

# --- Should be SKIPPED (non-firewall-cmd lines) ---
echo "Firewall configured"
systemctl restart firewalld
iptables -L
