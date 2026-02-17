# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-16

### Added

- YAML configuration parser with validation
- Template engine with variable substitution and loop expansion
- Command generator producing `firewall-cmd` apply and remove scripts
- Zone support: target, interfaces, sources, services, ports, rich rules, forward ports, ICMP blocks, protocols, masquerade, forward
- Direct rules: rules, passthroughs, chains
- Rule groups with `ipv: [ipv4, ipv6]` for cross-IP-version rule duplication
- Built-in `{{ ipv_any }}` variable (0.0.0.0/0 for ipv4, ::/0 for ipv6)
- CodeMirror YAML editor with syntax highlighting and live preview
- Apply and Remove output tabs with shell syntax highlighting
- Light and dark theme with system preference detection
- YAML import/export
- Copy-to-clipboard for generated scripts
- Example configuration for Docker + SSH server setup
- Responsive layout for desktop and mobile
- Docker deployment with nginx

[Unreleased]: https://github.com/studiowebux/firewalld/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/studiowebux/firewalld/releases/tag/v1.0.0
