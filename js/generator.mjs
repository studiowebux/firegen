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
 * Emit a command, optionally adding a runtime (non-permanent) duplicate.
 * @param {string[]} commands - output array
 * @param {string} cmd - the permanent command
 * @param {boolean} runtime - whether to also emit the runtime variant
 * @param {boolean} permanentOnly - if true, skip runtime even when runtime=true
 */
function emitCommand(commands, cmd, runtime, permanentOnly) {
  commands.push(cmd);
  if (runtime && !permanentOnly) {
    commands.push(cmd.replace(" --permanent", ""));
  }
}

/**
 * Generate zone commands with optional runtime duplication.
 */
function generateZoneCommandsDual(zoneName, zone, op, runtime) {
  const commands = [];
  const flag = `--${op}`;
  const perm = "--permanent";
  const z = `--zone=${zoneName}`;

  // Target (only for add, no remove equivalent — permanent-only)
  if (op === "add" && zone.target !== undefined) {
    emitCommand(commands, `${CMD} ${perm} ${z} --set-target=${zone.target}`, runtime, true);
  }

  if (Array.isArray(zone.interfaces)) {
    for (const iface of zone.interfaces) {
      const val = typeof iface === "object" ? iface.value : iface;
      emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-interface=${val}`, runtime, false);
    }
  }

  if (Array.isArray(zone.sources)) {
    for (const src of zone.sources) {
      const val = typeof src === "object" ? src.value : src;
      emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-source=${val}`, runtime, false);
    }
  }

  if (Array.isArray(zone.services)) {
    for (const svc of zone.services) {
      const val = typeof svc === "object" ? svc.value : svc;
      emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-service=${val}`, runtime, false);
    }
  }

  if (Array.isArray(zone.ports)) {
    for (const p of zone.ports) {
      if (typeof p === "object" && p.port !== undefined) {
        const proto = p.protocol || "tcp";
        emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-port=${p.port}/${proto}`, runtime, false);
      } else {
        emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-port=${p}`, runtime, false);
      }
    }
  }

  if (Array.isArray(zone.protocols)) {
    for (const proto of zone.protocols) {
      const val = typeof proto === "object" ? proto.value : proto;
      emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-protocol=${val}`, runtime, false);
    }
  }

  if (Array.isArray(zone.source_ports)) {
    for (const sp of zone.source_ports) {
      if (typeof sp === "object" && sp.port !== undefined) {
        const proto = sp.protocol || "tcp";
        emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-source-port=${sp.port}/${proto}`, runtime, false);
      } else {
        emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-source-port=${sp}`, runtime, false);
      }
    }
  }

  if (Array.isArray(zone.rich_rules)) {
    for (const rule of zone.rich_rules) {
      const richStr = buildRichRule(rule);
      emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-rich-rule='${richStr}'`, runtime, false);
    }
  }

  if (zone.forward === true) {
    emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-forward`, runtime, false);
  }

  if (zone.masquerade === true) {
    emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-masquerade`, runtime, false);
  }

  if (Array.isArray(zone.forward_ports)) {
    for (const fp of zone.forward_ports) {
      let val = `port=${fp.port}:proto=${fp.protocol || "tcp"}`;
      if (fp.to_port) {
        val += `:toport=${fp.to_port}`;
      }
      if (fp.to_addr) {
        val += `:toaddr=${fp.to_addr}`;
      }
      emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-forward-port=${val}`, runtime, false);
    }
  }

  if (Array.isArray(zone.icmp_blocks)) {
    for (const icmp of zone.icmp_blocks) {
      const val = typeof icmp === "object" ? icmp.value : icmp;
      emitCommand(commands, `${CMD} ${perm} ${z} ${flag}-icmp-block=${val}`, runtime, false);
    }
  }

  if (op === "add" && zone.icmp_block_inversion === true) {
    emitCommand(commands, `${CMD} ${perm} ${z} --add-icmp-block-inversion`, runtime, false);
  } else if (op === "remove" && zone.icmp_block_inversion === true) {
    emitCommand(commands, `${CMD} ${perm} ${z} --remove-icmp-block-inversion`, runtime, false);
  }

  return commands;
}

/**
 * Generate direct rule commands with optional runtime duplication.
 */
function generateDirectCommandsDual(direct, op, runtime) {
  const commands = [];
  const perm = "--permanent";

  if (Array.isArray(direct.chains)) {
    const seen = new Set();
    for (const c of direct.chains) {
      const key = `${c.ipv} ${c.table} ${c.chain}`;
      if (!seen.has(key)) {
        seen.add(key);
        emitCommand(commands, `${CMD} ${perm} --direct --${op}-chain ${c.ipv} ${c.table} ${c.chain}`, runtime, false);
      }
    }
  }

  if (Array.isArray(direct.rules)) {
    for (const r of direct.rules) {
      emitCommand(commands, `${CMD} ${perm} --direct --${op}-rule ${r.ipv} ${r.table} ${r.chain} ${r.priority} ${r.args}`, runtime, false);
    }
  }

  if (Array.isArray(direct.passthroughs)) {
    for (const pt of direct.passthroughs) {
      emitCommand(commands, `${CMD} ${perm} --direct --${op}-passthrough ${pt.ipv} ${pt.args}`, runtime, false);
    }
  }

  return commands;
}

/**
 * Generate the Apply script: add all rules then reload.
 * @param {object} config
 * @param {{ runtime?: boolean }} [options]
 */
export function generateApply(config, options) {
  if (!config) {
    return [];
  }

  const runtime = options?.runtime ?? false;
  const lines = ["#!/bin/bash", "# Generated by Firegen", "# Apply script: adds all configured rules", ""];

  if (config.zones) {
    for (const [zoneName, zone] of Object.entries(config.zones)) {
      lines.push(`# Zone: ${zoneName}`);
      lines.push(...generateZoneCommandsDual(zoneName, zone, "add", runtime));
      lines.push("");
    }
  }

  if (config.direct) {
    lines.push("# Direct rules");
    lines.push(...generateDirectCommandsDual(config.direct, "add", runtime));
    lines.push("");
  }

  if (!runtime) {
    lines.push("# Reload firewalld");
    lines.push(`${CMD} --reload`);
  }

  return lines;
}

/**
 * Generate the Remove script: remove all configured rules then reload.
 * @param {object} config
 * @param {{ runtime?: boolean }} [options]
 */
export function generateRemove(config, options) {
  if (!config) {
    return [];
  }

  const runtime = options?.runtime ?? false;
  const lines = ["#!/bin/bash", "# Generated by Firegen", "# Remove script: removes all configured rules", ""];

  // Remove direct rules first (reverse order from apply)
  if (config.direct) {
    lines.push("# Remove direct rules");
    lines.push(...generateDirectCommandsDual(config.direct, "remove", runtime));
    lines.push("");
  }

  if (config.zones) {
    for (const [zoneName, zone] of Object.entries(config.zones)) {
      lines.push(`# Zone: ${zoneName}`);
      lines.push(...generateZoneCommandsDual(zoneName, zone, "remove", runtime));
      lines.push("");
    }
  }

  if (!runtime) {
    lines.push("# Reload firewalld");
    lines.push(`${CMD} --reload`);
  }

  return lines;
}

