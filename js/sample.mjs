// Default example YAML configuration

export const SAMPLE_YAML = `# Firewalld YAML Configuration
# Use variables, loops, and rule_groups to keep your config DRY

variables:
  trusted_ips:
    - 10.0.0.1
    - 10.0.0.2
    - 10.0.0.3
  web_ports:
    - 80
    - 443
    - 8080
  ssh_port: 2222
  internal_net: 192.168.1.0/24

zones:
  public:
    target: default
    interfaces:
      - eth0
    services:
      - http
      - https
      - dns
    ports:
      - port: "{{ item }}"
        protocol: tcp
        loop: "{{ web_ports }}"
      - port: "{{ ssh_port }}"
        protocol: tcp
    sources:
      - "{{ internal_net }}"
    rich_rules:
      - family: ipv4
        source: "{{ item }}"
        port: 443
        protocol: tcp
        action: accept
        loop: "{{ trusted_ips }}"
      - family: ipv4
        source: "{{ internal_net }}"
        service: ssh
        log:
          prefix: "ssh-access"
          level: info
        action: accept
    forward_ports:
      - port: 8443
        protocol: tcp
        to_port: 443
        to_addr: 192.168.1.10
    icmp_blocks:
      - echo-reply
      - timestamp-request
    protocols:
      - gre

  trusted:
    target: ACCEPT
    sources:
      - value: "{{ item }}"
        loop: "{{ trusted_ips }}"
    interfaces:
      - lo

direct:
  rule_groups:
    - ipv: [ipv4, ipv6]
      table: filter
      chain: DOCKER-USER
      rules:
        - priority: 1
          args: "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        - priority: 1
          args: "-j RETURN -s {{ item }}"
          loop: "{{ trusted_ips }}"
        - priority: 1
          args: "-j RETURN -s {{ ipv_any }} -p tcp --dport {{ item }}"
          loop: "{{ web_ports }}"
        - priority: 10
          args: "-j DROP"
  passthroughs:
    - ipv: ipv4
      args: "-A FORWARD -p icmp -j ACCEPT"
`;
