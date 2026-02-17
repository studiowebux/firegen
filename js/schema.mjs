// Pattern: Registry — single source of truth for all valid YAML config keys

export const VALID_TOP_KEYS = new Set(["variables", "zones", "direct"]);

export const VALID_ZONE_KEYS = new Set([
  "target",
  "interfaces",
  "sources",
  "services",
  "ports",
  "protocols",
  "source_ports",
  "rich_rules",
  "forward",
  "masquerade",
  "forward_ports",
  "icmp_blocks",
  "icmp_block_inversion",
]);

export const VALID_PORT_KEYS = new Set(["port", "protocol", "loop"]);

export const VALID_FORWARD_PORT_KEYS = new Set(["port", "protocol", "to_port", "to_addr", "loop"]);

export const VALID_RICH_RULE_KEYS = new Set([
  "family", "source", "source_invert", "destination", "destination_invert",
  "service", "port", "protocol", "icmp_block", "icmp_type", "masquerade",
  "forward_port", "source_port", "log", "audit", "action", "reject_type",
  "mark_set", "loop",
]);

export const VALID_DIRECT_KEYS = new Set(["chains", "rules", "passthroughs", "rule_groups"]);

export const VALID_DIRECT_RULE_KEYS = new Set(["ipv", "table", "chain", "priority", "args", "loop"]);

export const VALID_DIRECT_CHAIN_KEYS = new Set(["ipv", "table", "chain"]);

export const VALID_PASSTHROUGH_KEYS = new Set(["ipv", "args", "loop"]);

export const VALID_RULE_GROUP_KEYS = new Set(["ipv", "table", "chain", "rules", "passthroughs"]);

export const VALID_RULE_GROUP_RULE_KEYS = new Set(["priority", "args", "loop"]);

export const VALID_TARGETS = ["default", "ACCEPT", "DROP", "REJECT"];
