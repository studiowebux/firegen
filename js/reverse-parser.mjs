// Pattern: Parser — transforms firewall-cmd command text into a config object

/**
 * Tokenize a firewall-cmd command line, preserving single-quoted strings.
 * Returns an array of tokens (flags, values, positional args).
 */
function tokenizeLine(line) {
  const tokens = [];
  let i = 0;
  const len = line.length;

  while (i < len) {
    // Skip whitespace
    while (i < len && line[i] === " ") {
      i++;
    }
    if (i >= len) {
      break;
    }

    // Single-quoted string
    if (line[i] === "'") {
      i++;
      let str = "";
      while (i < len && line[i] !== "'") {
        str += line[i];
        i++;
      }
      i++; // skip closing quote
      tokens.push(str);
      continue;
    }

    // Regular token (until whitespace), with inline single-quote support
    let token = "";
    while (i < len && line[i] !== " ") {
      if (line[i] === "'") {
        // Inline quoted string (e.g. --add-rich-rule='rule ...')
        i++; // skip opening quote
        let quoted = "";
        while (i < len && line[i] !== "'") {
          quoted += line[i];
          i++;
        }
        if (i < len) {
          i++; // skip closing quote
        }
        token += quoted;
      } else {
        token += line[i];
        i++;
      }
    }
    tokens.push(token);
  }

  return tokens;
}

/**
 * Parse tokens into a flags map and positional args.
 * Flags: --key=value -> { key: value }, --flag -> { flag: true }
 */
function parseFlags(tokens) {
  const flags = {};
  const args = [];

  for (const token of tokens) {
    if (token.startsWith("--")) {
      const eqIdx = token.indexOf("=");
      if (eqIdx !== -1) {
        const key = token.slice(2, eqIdx);
        const value = token.slice(eqIdx + 1);
        flags[key] = value;
      } else {
        flags[token.slice(2)] = true;
      }
    } else if (token !== "firewall-cmd" && token !== "sudo") {
      args.push(token);
    }
  }

  return { flags, args };
}

/**
 * Parse a port/protocol string "80/tcp" into { port, protocol }.
 */
function parsePort(value) {
  const slashIdx = value.indexOf("/");
  if (slashIdx === -1) {
    return { port: value, protocol: "tcp" };
  }
  return { port: value.slice(0, slashIdx), protocol: value.slice(slashIdx + 1) };
}

/**
 * Parse a forward-port value "port=P:proto=PR[:toport=T][:toaddr=A]".
 */
function parseForwardPort(value) {
  const result = {};
  const parts = value.split(":");

  for (const part of parts) {
    const eqIdx = part.indexOf("=");
    if (eqIdx === -1) {
      continue;
    }
    const key = part.slice(0, eqIdx);
    const val = part.slice(eqIdx + 1);

    if (key === "port") {
      result.port = val;
    } else if (key === "proto") {
      result.protocol = val;
    } else if (key === "toport") {
      result.to_port = val;
    } else if (key === "toaddr") {
      result.to_addr = val;
    }
  }

  return result;
}

/**
 * Parse a rich rule string into an object matching the YAML schema.
 *
 * Tokenizes the string respecting key="value" pairs and walks tokens
 * left-to-right matching known keywords.
 */
function parseRichRule(ruleStr) {
  // Tokenize: split on spaces but keep key="value" together
  const rawTokens = [];
  let i = 0;
  const len = ruleStr.length;

  while (i < len) {
    while (i < len && ruleStr[i] === " ") {
      i++;
    }
    if (i >= len) {
      break;
    }

    let token = "";
    while (i < len && ruleStr[i] !== " ") {
      if (ruleStr[i] === '"') {
        // Include the quoted value as part of this token
        token += ruleStr[i];
        i++;
        while (i < len && ruleStr[i] !== '"') {
          token += ruleStr[i];
          i++;
        }
        if (i < len) {
          token += ruleStr[i]; // closing quote
          i++;
        }
      } else {
        token += ruleStr[i];
        i++;
      }
    }
    rawTokens.push(token);
  }

  const rule = {};

  /**
   * Extract a quoted value from a token like key="value".
   */
  function extractValue(token) {
    const eqIdx = token.indexOf("=");
    if (eqIdx === -1) {
      return token;
    }
    let val = token.slice(eqIdx + 1);
    if (val.startsWith('"') && val.endsWith('"')) {
      val = val.slice(1, -1);
    }
    return val;
  }

  /**
   * Get the attribute name from key="value" token.
   */
  function attrName(token) {
    const eqIdx = token.indexOf("=");
    return eqIdx === -1 ? token : token.slice(0, eqIdx);
  }

  let pos = 0;

  // Skip the "rule" keyword
  if (pos < rawTokens.length && rawTokens[pos] === "rule") {
    pos++;
  }

  // family="..."
  if (pos < rawTokens.length && attrName(rawTokens[pos]) === "family") {
    rule.family = extractValue(rawTokens[pos]);
    pos++;
  }

  // source address="..." [invert="true"]
  if (pos < rawTokens.length && rawTokens[pos] === "source") {
    pos++;
    if (pos < rawTokens.length && attrName(rawTokens[pos]) === "address") {
      rule.source = extractValue(rawTokens[pos]);
      pos++;
    }
    if (pos < rawTokens.length && attrName(rawTokens[pos]) === "invert") {
      if (extractValue(rawTokens[pos]) === "true") {
        rule.source_invert = true;
      }
      pos++;
    }
  }

  // destination address="..." [invert="true"]
  if (pos < rawTokens.length && rawTokens[pos] === "destination") {
    pos++;
    if (pos < rawTokens.length && attrName(rawTokens[pos]) === "address") {
      rule.destination = extractValue(rawTokens[pos]);
      pos++;
    }
    if (pos < rawTokens.length && attrName(rawTokens[pos]) === "invert") {
      if (extractValue(rawTokens[pos]) === "true") {
        rule.destination_invert = true;
      }
      pos++;
    }
  }

  // Element: service, port, protocol, icmp-block, icmp-type, masquerade, forward-port, source-port
  if (pos < rawTokens.length) {
    const keyword = rawTokens[pos];

    if (keyword === "service") {
      pos++;
      if (pos < rawTokens.length && attrName(rawTokens[pos]) === "name") {
        rule.service = extractValue(rawTokens[pos]);
        pos++;
      }
    } else if (keyword === "port") {
      pos++;
      while (pos < rawTokens.length) {
        const attr = attrName(rawTokens[pos]);
        if (attr === "port") {
          rule.port = extractValue(rawTokens[pos]);
        } else if (attr === "protocol") {
          rule.protocol = extractValue(rawTokens[pos]);
        } else {
          break;
        }
        pos++;
      }
    } else if (keyword === "protocol") {
      pos++;
      if (pos < rawTokens.length && attrName(rawTokens[pos]) === "value") {
        rule.protocol = extractValue(rawTokens[pos]);
        pos++;
      }
    } else if (keyword === "icmp-block") {
      pos++;
      if (pos < rawTokens.length && attrName(rawTokens[pos]) === "name") {
        rule.icmp_block = extractValue(rawTokens[pos]);
        pos++;
      }
    } else if (keyword === "icmp-type") {
      pos++;
      if (pos < rawTokens.length && attrName(rawTokens[pos]) === "name") {
        rule.icmp_type = extractValue(rawTokens[pos]);
        pos++;
      }
    } else if (keyword === "masquerade") {
      rule.masquerade = true;
      pos++;
    } else if (keyword === "forward-port") {
      pos++;
      const fp = {};
      while (pos < rawTokens.length) {
        const attr = attrName(rawTokens[pos]);
        if (attr === "port") {
          fp.port = extractValue(rawTokens[pos]);
        } else if (attr === "protocol") {
          fp.protocol = extractValue(rawTokens[pos]);
        } else if (attr === "to-port") {
          fp.to_port = extractValue(rawTokens[pos]);
        } else if (attr === "to-addr") {
          fp.to_addr = extractValue(rawTokens[pos]);
        } else {
          break;
        }
        pos++;
      }
      rule.forward_port = fp;
    } else if (keyword === "source-port") {
      pos++;
      const sp = {};
      while (pos < rawTokens.length) {
        const attr = attrName(rawTokens[pos]);
        if (attr === "port") {
          sp.port = extractValue(rawTokens[pos]);
        } else if (attr === "protocol") {
          sp.protocol = extractValue(rawTokens[pos]);
        } else {
          break;
        }
        pos++;
      }
      rule.source_port = sp;
    }
  }

  // log [prefix="..." level="..." limit value="..."]
  if (pos < rawTokens.length && rawTokens[pos] === "log") {
    pos++;
    const logObj = {};
    while (pos < rawTokens.length) {
      const attr = attrName(rawTokens[pos]);
      if (attr === "prefix") {
        logObj.prefix = extractValue(rawTokens[pos]);
        pos++;
      } else if (attr === "level") {
        logObj.level = extractValue(rawTokens[pos]);
        pos++;
      } else if (attr === "limit") {
        pos++;
        if (pos < rawTokens.length && attrName(rawTokens[pos]) === "value") {
          logObj.limit = extractValue(rawTokens[pos]);
          pos++;
        }
      } else {
        break;
      }
    }
    rule.log = logObj;
  }

  // audit
  if (pos < rawTokens.length && rawTokens[pos] === "audit") {
    rule.audit = true;
    pos++;
  }

  // Action: accept, reject [type="..."], drop, mark [set="..."]
  if (pos < rawTokens.length) {
    const action = rawTokens[pos];
    if (action === "accept" || action === "drop") {
      rule.action = action;
      pos++;
    } else if (action === "reject") {
      rule.action = "reject";
      pos++;
      if (pos < rawTokens.length && attrName(rawTokens[pos]) === "type") {
        rule.reject_type = extractValue(rawTokens[pos]);
        pos++;
      }
    } else if (action === "mark") {
      rule.action = "mark";
      pos++;
      if (pos < rawTokens.length && attrName(rawTokens[pos]) === "set") {
        rule.mark_set = extractValue(rawTokens[pos]);
        pos++;
      }
    }
  }

  return rule;
}

/**
 * Ensure a zone exists in the config and return it.
 */
function ensureZone(config, zoneName) {
  if (!config.zones[zoneName]) {
    config.zones[zoneName] = {};
  }
  return config.zones[zoneName];
}

/**
 * Normalize an --add-* or --remove-* flag name to the base name.
 * e.g. "add-service" -> "service", "remove-port" -> "port"
 */
function normalizeFlag(flag) {
  if (flag.startsWith("add-")) {
    return flag.slice(4);
  }
  if (flag.startsWith("remove-")) {
    return flag.slice(7);
  }
  return flag;
}

/**
 * Process a zone command given the parsed flags.
 */
function processZoneCommand(zone, flags) {
  // Find the action flag (add-* or remove-* or set-target)
  for (const [key, value] of Object.entries(flags)) {
    if (key === "zone" || key === "permanent" || key === "direct") {
      continue;
    }

    const base = normalizeFlag(key);

    if (key === "set-target") {
      zone.target = value;
      return true;
    }

    if (base === "interface") {
      if (!zone.interfaces) {
        zone.interfaces = [];
      }
      zone.interfaces.push(value);
      return true;
    }

    if (base === "source") {
      if (!zone.sources) {
        zone.sources = [];
      }
      zone.sources.push(value);
      return true;
    }

    if (base === "service") {
      if (!zone.services) {
        zone.services = [];
      }
      zone.services.push(value);
      return true;
    }

    if (base === "port") {
      if (!zone.ports) {
        zone.ports = [];
      }
      zone.ports.push(parsePort(value));
      return true;
    }

    if (base === "protocol") {
      if (!zone.protocols) {
        zone.protocols = [];
      }
      zone.protocols.push(value);
      return true;
    }

    if (base === "source-port") {
      if (!zone.source_ports) {
        zone.source_ports = [];
      }
      zone.source_ports.push(parsePort(value));
      return true;
    }

    if (base === "rich-rule") {
      if (!zone.rich_rules) {
        zone.rich_rules = [];
      }
      zone.rich_rules.push(parseRichRule(value));
      return true;
    }

    if (base === "forward" && value === true) {
      zone.forward = true;
      return true;
    }

    if (base === "masquerade" && value === true) {
      zone.masquerade = true;
      return true;
    }

    if (base === "forward-port") {
      if (!zone.forward_ports) {
        zone.forward_ports = [];
      }
      zone.forward_ports.push(parseForwardPort(value));
      return true;
    }

    if (base === "icmp-block" && typeof value === "string") {
      if (!zone.icmp_blocks) {
        zone.icmp_blocks = [];
      }
      zone.icmp_blocks.push(value);
      return true;
    }

    if (base === "icmp-block-inversion") {
      zone.icmp_block_inversion = true;
      return true;
    }
  }

  return false;
}

/**
 * Process a direct command.
 * Direct commands use positional args after the --add-chain/rule/passthrough flag.
 */
function processDirectCommand(config, flags, tokens) {
  // Find the direct action flag
  const directAction = Object.keys(flags).find(
    (k) =>
      k === "add-chain" ||
      k === "remove-chain" ||
      k === "add-rule" ||
      k === "remove-rule" ||
      k === "add-passthrough" ||
      k === "remove-passthrough"
  );

  if (!directAction) {
    return false;
  }

  // Find the position of the direct action flag in the original tokens
  // to extract positional args after it
  const flagToken = `--${directAction}`;
  const flagIdx = tokens.indexOf(flagToken);
  if (flagIdx === -1) {
    return false;
  }

  const positional = tokens.slice(flagIdx + 1);
  const base = normalizeFlag(directAction);

  if (base === "chain") {
    // ipv table chain
    if (positional.length >= 3) {
      config.direct.chains.push({
        ipv: positional[0],
        table: positional[1],
        chain: positional[2],
      });
      return true;
    }
  }

  if (base === "rule") {
    // ipv table chain priority args...
    if (positional.length >= 5) {
      config.direct.rules.push({
        ipv: positional[0],
        table: positional[1],
        chain: positional[2],
        priority: parseInt(positional[3], 10),
        args: positional.slice(4).join(" "),
      });
      return true;
    }
  }

  if (base === "passthrough") {
    // ipv args...
    if (positional.length >= 2) {
      config.direct.passthroughs.push({
        ipv: positional[0],
        args: positional.slice(1).join(" "),
      });
      return true;
    }
  }

  return false;
}

/**
 * Deduplicate direct chains (same ipv+table+chain).
 */
function deduplicateChains(chains) {
  const seen = new Set();
  return chains.filter((c) => {
    const key = `${c.ipv}|${c.table}|${c.chain}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

/**
 * Remove empty sections from the config to produce clean YAML output.
 */
function cleanConfig(config) {
  const result = {};

  if (Object.keys(config.zones).length > 0) {
    result.zones = config.zones;
  }

  const hasChains = config.direct.chains.length > 0;
  const hasRules = config.direct.rules.length > 0;
  const hasPassthroughs = config.direct.passthroughs.length > 0;

  if (hasChains || hasRules || hasPassthroughs) {
    result.direct = {};
    if (hasChains) {
      result.direct.chains = deduplicateChains(config.direct.chains);
    }
    if (hasRules) {
      result.direct.rules = config.direct.rules;
    }
    if (hasPassthroughs) {
      result.direct.passthroughs = config.direct.passthroughs;
    }
  }

  return result;
}

/**
 * Parse a block of firewall-cmd commands into a config object.
 *
 * @param {string} text - multiline text containing firewall-cmd commands
 * @returns {{ config: object, errors: string[], skipped: string[] }}
 */
export function parseCommands(text) {
  const config = {
    zones: {},
    direct: { chains: [], rules: [], passthroughs: [] },
  };

  const errors = [];
  const skipped = [];

  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();

    // Skip blank lines
    if (trimmed === "") {
      continue;
    }

    // Skip comments and shebang
    if (trimmed.startsWith("#") || trimmed.startsWith("#!/")) {
      skipped.push(`Line ${i + 1}: ${trimmed}`);
      continue;
    }

    // Strip sudo prefix
    let line = trimmed;
    if (line.startsWith("sudo ")) {
      line = line.slice(5);
    }

    // Must start with firewall-cmd
    if (!line.startsWith("firewall-cmd")) {
      skipped.push(`Line ${i + 1}: ${trimmed}`);
      continue;
    }

    // Reject lines containing shell variables
    if (/\$(?:\w|\{|\()/.test(line)) {
      errors.push(`Line ${i + 1}: shell variables not supported (expand variables before importing)`);
      continue;
    }

    const tokens = tokenizeLine(line);
    const { flags } = parseFlags(tokens);

    // Remove --permanent (irrelevant for parsing)
    delete flags.permanent;

    // Skip reload commands (any firewall-cmd with --reload or --complete-reload)
    if (flags["reload"] || flags["complete-reload"]) {
      skipped.push(`Line ${i + 1}: reload command`);
      continue;
    }

    // Skip non-modifying / query commands gracefully
    const skipFlags = ["runtime-to-permanent", "check-config", "state", "version"];
    const skipPrefixes = ["get-", "list-", "query-"];
    const flagKeys = Object.keys(flags);
    const isSkippable = flagKeys.some(
      (k) => skipFlags.includes(k) || skipPrefixes.some((p) => k.startsWith(p))
    );
    if (isSkippable) {
      skipped.push(`Line ${i + 1}: non-modifying command (${trimmed})`);
      continue;
    }

    // Direct commands
    if (flags.direct) {
      if (!processDirectCommand(config, flags, tokens)) {
        errors.push(`Line ${i + 1}: could not parse direct command: ${trimmed}`);
      }
      continue;
    }

    // Zone commands — infer "public" when no --zone and command has modifying flags
    let zoneName = flags.zone;
    if (!zoneName) {
      const hasModifying = flagKeys.some(
        (k) => k.startsWith("add-") || k.startsWith("remove-") || k === "set-target"
      );
      if (hasModifying) {
        zoneName = "public";
      }
    }

    if (zoneName) {
      delete flags.zone;
      const zone = ensureZone(config, zoneName);
      if (!processZoneCommand(zone, flags)) {
        errors.push(`Line ${i + 1}: could not parse zone command: ${trimmed}`);
      }
      continue;
    }

    // Unknown command structure
    errors.push(`Line ${i + 1}: unrecognized command: ${trimmed}`);
  }

  return {
    config: cleanConfig(config),
    errors,
    skipped,
  };
}
