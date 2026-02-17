// Pattern: Strategy — two generation strategies (apply, remove) sharing zone/direct walkers

const CMD = "firewall-cmd";

/**
 * Build a rich rule string from a rich_rules entry object.
 */
function buildRichRule(rule) {
  const parts = ["rule"];

  if (rule.family) {
    parts.push(`family="${rule.family}"`);
  }
  if (rule.source) {
    const invert = rule.source_invert ? ' invert="true"' : "";
    parts.push(`source address="${rule.source}"${invert}`);
  }
  if (rule.destination) {
    const invert = rule.destination_invert ? ' invert="true"' : "";
    parts.push(`destination address="${rule.destination}"${invert}`);
  }
  if (rule.service) {
    parts.push(`service name="${rule.service}"`);
  }
  if (rule.port && rule.protocol) {
    parts.push(`port port="${rule.port}" protocol="${rule.protocol}"`);
  }
  if (rule.protocol && !rule.port) {
    parts.push(`protocol value="${rule.protocol}"`);
  }
  if (rule.icmp_block) {
    parts.push(`icmp-block name="${rule.icmp_block}"`);
  }
  if (rule.icmp_type) {
    parts.push(`icmp-type name="${rule.icmp_type}"`);
  }
  if (rule.masquerade) {
    parts.push("masquerade");
  }
  if (rule.forward_port) {
    let fp = `forward-port port="${rule.forward_port.port}" protocol="${rule.forward_port.protocol}"`;
    if (rule.forward_port.to_port) {
      fp += ` to-port="${rule.forward_port.to_port}"`;
    }
    if (rule.forward_port.to_addr) {
      fp += ` to-addr="${rule.forward_port.to_addr}"`;
    }
    parts.push(fp);
  }
  if (rule.source_port) {
    parts.push(`source-port port="${rule.source_port.port}" protocol="${rule.source_port.protocol}"`);
  }
  if (rule.log) {
    let logStr = "log";
    if (rule.log.prefix) {
      logStr += ` prefix="${rule.log.prefix}"`;
    }
    if (rule.log.level) {
      logStr += ` level="${rule.log.level}"`;
    }
    if (rule.log.limit) {
      logStr += ` limit value="${rule.log.limit}"`;
    }
    parts.push(logStr);
  }
  if (rule.audit) {
    parts.push("audit");
  }

  // Action (must be last)
  if (rule.action) {
    const action = String(rule.action).toLowerCase();
    if (action === "reject" && rule.reject_type) {
      parts.push(`reject type="${rule.reject_type}"`);
    } else if (action === "mark" && rule.mark_set) {
      parts.push(`mark set="${rule.mark_set}"`);
    } else {
      parts.push(action);
    }
  }

  return parts.join(" ");
}

/**
 * Generate zone commands for a single zone.
 * @param {string} zoneName
 * @param {object} zone - zone config
 * @param {string} op - "add" or "remove"
 * @returns {string[]} commands
 */
function generateZoneCommands(zoneName, zone, op) {
  const commands = [];
  const flag = `--${op}`;
  const perm = "--permanent";
  const z = `--zone=${zoneName}`;

  // Target (only for add, no remove equivalent)
  if (op === "add" && zone.target !== undefined) {
    commands.push(`${CMD} ${perm} ${z} --set-target=${zone.target}`);
  }

  // Interfaces
  if (Array.isArray(zone.interfaces)) {
    for (const iface of zone.interfaces) {
      const val = typeof iface === "object" ? iface.value : iface;
      commands.push(`${CMD} ${perm} ${z} ${flag}-interface=${val}`);
    }
  }

  // Sources
  if (Array.isArray(zone.sources)) {
    for (const src of zone.sources) {
      const val = typeof src === "object" ? src.value : src;
      commands.push(`${CMD} ${perm} ${z} ${flag}-source=${val}`);
    }
  }

  // Services
  if (Array.isArray(zone.services)) {
    for (const svc of zone.services) {
      const val = typeof svc === "object" ? svc.value : svc;
      commands.push(`${CMD} ${perm} ${z} ${flag}-service=${val}`);
    }
  }

  // Ports
  if (Array.isArray(zone.ports)) {
    for (const p of zone.ports) {
      if (typeof p === "object" && p.port !== undefined) {
        const proto = p.protocol || "tcp";
        commands.push(`${CMD} ${perm} ${z} ${flag}-port=${p.port}/${proto}`);
      } else {
        commands.push(`${CMD} ${perm} ${z} ${flag}-port=${p}`);
      }
    }
  }

  // Protocols
  if (Array.isArray(zone.protocols)) {
    for (const proto of zone.protocols) {
      const val = typeof proto === "object" ? proto.value : proto;
      commands.push(`${CMD} ${perm} ${z} ${flag}-protocol=${val}`);
    }
  }

  // Source ports
  if (Array.isArray(zone.source_ports)) {
    for (const sp of zone.source_ports) {
      if (typeof sp === "object" && sp.port !== undefined) {
        const proto = sp.protocol || "tcp";
        commands.push(`${CMD} ${perm} ${z} ${flag}-source-port=${sp.port}/${proto}`);
      } else {
        commands.push(`${CMD} ${perm} ${z} ${flag}-source-port=${sp}`);
      }
    }
  }

  // Rich rules
  if (Array.isArray(zone.rich_rules)) {
    for (const rule of zone.rich_rules) {
      const richStr = buildRichRule(rule);
      commands.push(`${CMD} ${perm} ${z} ${flag}-rich-rule='${richStr}'`);
    }
  }

  // Forward (IP forwarding)
  if (zone.forward === true) {
    commands.push(`${CMD} ${perm} ${z} ${flag}-forward`);
  }

  // Masquerade
  if (zone.masquerade === true) {
    commands.push(`${CMD} ${perm} ${z} ${flag}-masquerade`);
  }

  // Forward ports
  if (Array.isArray(zone.forward_ports)) {
    for (const fp of zone.forward_ports) {
      let val = `port=${fp.port}:proto=${fp.protocol || "tcp"}`;
      if (fp.to_port) {
        val += `:toport=${fp.to_port}`;
      }
      if (fp.to_addr) {
        val += `:toaddr=${fp.to_addr}`;
      }
      commands.push(`${CMD} ${perm} ${z} ${flag}-forward-port=${val}`);
    }
  }

  // ICMP blocks
  if (Array.isArray(zone.icmp_blocks)) {
    for (const icmp of zone.icmp_blocks) {
      const val = typeof icmp === "object" ? icmp.value : icmp;
      commands.push(`${CMD} ${perm} ${z} ${flag}-icmp-block=${val}`);
    }
  }

  // ICMP block inversion (only for add)
  if (op === "add" && zone.icmp_block_inversion === true) {
    commands.push(`${CMD} ${perm} ${z} --add-icmp-block-inversion`);
  } else if (op === "remove" && zone.icmp_block_inversion === true) {
    commands.push(`${CMD} ${perm} ${z} --remove-icmp-block-inversion`);
  }

  return commands;
}

/**
 * Generate direct rule commands.
 * @param {object} direct - direct config block
 * @param {string} op - "add" or "remove"
 * @returns {string[]}
 */
function generateDirectCommands(direct, op) {
  const commands = [];
  const perm = "--permanent";

  // Chains (deduplicate — rule_groups can produce duplicates)
  if (Array.isArray(direct.chains)) {
    const seen = new Set();
    for (const c of direct.chains) {
      const key = `${c.ipv} ${c.table} ${c.chain}`;
      if (!seen.has(key)) {
        seen.add(key);
        commands.push(`${CMD} ${perm} --direct --${op}-chain ${c.ipv} ${c.table} ${c.chain}`);
      }
    }
  }

  // Rules
  if (Array.isArray(direct.rules)) {
    for (const r of direct.rules) {
      commands.push(`${CMD} ${perm} --direct --${op}-rule ${r.ipv} ${r.table} ${r.chain} ${r.priority} ${r.args}`);
    }
  }

  // Passthroughs
  if (Array.isArray(direct.passthroughs)) {
    for (const pt of direct.passthroughs) {
      commands.push(`${CMD} ${perm} --direct --${op}-passthrough ${pt.ipv} ${pt.args}`);
    }
  }

  return commands;
}

/**
 * Generate the Apply script: add all rules then reload.
 */
export function generateApply(config) {
  if (!config) {
    return [];
  }

  const lines = ["#!/bin/bash", "# Generated by Firegen", "# Apply script: adds all configured rules", ""];

  if (config.zones) {
    for (const [zoneName, zone] of Object.entries(config.zones)) {
      lines.push(`# Zone: ${zoneName}`);
      lines.push(...generateZoneCommands(zoneName, zone, "add"));
      lines.push("");
    }
  }

  if (config.direct) {
    lines.push("# Direct rules");
    lines.push(...generateDirectCommands(config.direct, "add"));
    lines.push("");
  }

  lines.push("# Reload firewalld");
  lines.push(`${CMD} --reload`);

  return lines;
}

/**
 * Generate the Remove script: remove all configured rules then reload.
 */
export function generateRemove(config) {
  if (!config) {
    return [];
  }

  const lines = ["#!/bin/bash", "# Generated by Firegen", "# Remove script: removes all configured rules", ""];

  // Remove direct rules first (reverse order from apply)
  if (config.direct) {
    lines.push("# Remove direct rules");
    lines.push(...generateDirectCommands(config.direct, "remove"));
    lines.push("");
  }

  if (config.zones) {
    for (const [zoneName, zone] of Object.entries(config.zones)) {
      lines.push(`# Zone: ${zoneName}`);
      lines.push(...generateZoneCommands(zoneName, zone, "remove"));
      lines.push("");
    }
  }

  lines.push("# Reload firewalld");
  lines.push(`${CMD} --reload`);

  return lines;
}

