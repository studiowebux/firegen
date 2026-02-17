# Firegen

Declarative firewalld configuration generator. Write YAML, get `firewall-cmd` scripts.

**Bug tracker:** [GitHub Issues](https://github.com/studiowebux/firewalld/issues) | **Discord:** [Join](https://discord.gg/BG5Erm9fNv)

**Funding:** [Buy Me a Coffee](https://buymeacoffee.com/studiowebux) | [GitHub Sponsors](https://github.com/sponsors/studiowebux) | [Patreon](https://patreon.com/studiowebux)

## About

Firegen takes a YAML configuration describing firewalld zones, ports, services, rich rules, and direct rules, then generates ready-to-run `firewall-cmd` apply and remove scripts. It supports variables, loops, and `rule_groups` to keep configurations DRY across IPv4/IPv6.

Runs entirely in the browser. No backend, no telemetry, no dependencies at runtime.

## Installation

### From source

```sh
git clone https://github.com/studiowebux/firewalld.git
cd firewalld
python3 -m http.server 8090
```

Open `http://localhost:8090`.

### Docker

```sh
docker compose up -d
```

Open `http://localhost:8090`.

### Static hosting

Copy the repo contents to any static file server (nginx, Caddy, S3, GitHub Pages). No build step required.

## Usage

Write YAML in the left panel. Generated `firewall-cmd` commands appear in the right panel under Apply and Remove tabs.

```yaml
variables:
  web_ports:
    - 80
    - 443

zones:
  public:
    target: DROP
    interfaces:
      - eth0
    services:
      - ssh
    ports:
      - port: "{{ item }}"
        protocol: tcp
        loop: "{{ web_ports }}"
```

### Variables

Define reusable values under `variables:`. Reference them with `{{ variable_name }}`. List variables expand in `loop:` directives.

### Loops

Add `loop: "{{ list_variable }}"` to any array item. The item is duplicated for each value, with `{{ item }}` replaced by the current value.

### Rule groups

Use `rule_groups` under `direct:` to share rules across IP versions:

```yaml
direct:
  rule_groups:
    - ipv: [ipv4, ipv6]
      table: filter
      chain: DOCKER-USER
      rules:
        - priority: 1
          args: "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        - priority: 10
          args: "-j DROP"
```

The built-in `{{ ipv_any }}` variable resolves to `0.0.0.0/0` for ipv4 and `::/0` for ipv6.

### Import / Export

Use the Import and Export buttons to load and save YAML configuration files.

## Getting Started

1. Open the app and review the preloaded example
2. Modify the YAML or import your own configuration
3. Copy the Apply script and run it on your server
4. Keep the Remove script to roll back changes

See `examples/docker-firewall.yaml` for a production configuration protecting Docker containers behind firewalld.

## Contributions

Contributions are welcome. Open an issue first to discuss changes.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contact

[Studio Webux](https://studiowebux.com) | [Discord](https://discord.gg/BG5Erm9fNv) | tommy@studiowebux.com
