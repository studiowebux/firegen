// Pattern: Facade — wraps js-yaml parsing with validation and template processing

import { processTemplate } from "./template-engine.mjs";
import {
  VALID_TOP_KEYS, VALID_ZONE_KEYS, VALID_PORT_KEYS, VALID_FORWARD_PORT_KEYS,
  VALID_RICH_RULE_KEYS, VALID_DIRECT_KEYS, VALID_DIRECT_RULE_KEYS,
  VALID_DIRECT_CHAIN_KEYS, VALID_PASSTHROUGH_KEYS, VALID_RULE_GROUP_KEYS,
  VALID_RULE_GROUP_RULE_KEYS, VALID_TARGETS,
} from "./schema.mjs";

/**
 * Find the 0-based line number of a key in raw YAML text.
 * Searches for `key:` (mapping) or `- key` (sequence item) patterns.
 * Uses optional parentKey to narrow scope to the correct section.
 * Returns 0-based line number or null if not found.
 */
function findKeyLine(yamlString, key, parentKey) {
  const lines = yamlString.split("\n");

  let searchStart = 0;
  let parentIndent = -1;

  // If parentKey provided, find it first and search below it
  if (parentKey) {
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimStart();
      if (trimmed.startsWith(`${parentKey}:`) || trimmed.startsWith(`${parentKey} :`)) {
        searchStart = i + 1;
        parentIndent = lines[i].length - trimmed.length;
        break;
      }
    }
  }

  const keyPattern = new RegExp(`^(\\s*(-\\s+)?)(${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})\\s*:`);

  for (let i = searchStart; i < lines.length; i++) {
    const match = lines[i].match(keyPattern);
    if (match) {
      // If scoped by parent, ensure this line is indented deeper
      if (parentKey && parentIndent >= 0) {
        const lineIndent = match[1].replace(/-\s+$/, "").length;
        if (lineIndent <= parentIndent) break; // Left parent scope
        if (lineIndent > parentIndent) return i;
      } else {
        return i;
      }
    }
    // If scoped by parent, stop if we reach another key at same/lesser indent
    if (parentKey && parentIndent >= 0 && i > searchStart) {
      const trimmed = lines[i].trimStart();
      if (trimmed.length > 0 && !trimmed.startsWith("#")) {
        const lineIndent = lines[i].length - trimmed.length;
        if (lineIndent <= parentIndent && trimmed.includes(":")) break;
      }
    }
  }

  return null;
}

/**
 * Adjust js-yaml syntax error line to point at the actual cause.
 *
 * js-yaml reports the detection point, not where the mistake is:
 *   - Missing colon: mark points to the NEXT line (unexpected indentation)
 *   - Missing quote: mark points past EOF (stream ended inside literal)
 *
 * This heuristic corrects the line for common cases.
 */
function adjustSyntaxErrorLine(line, reason, yamlString) {
  if (line === null || !reason) return line;

  const lines = yamlString.split("\n");
  const lastLine = lines.length - 1;

  // Missing quote: error detected at EOF. Find the line with the unclosed quote.
  // Patterns: "double quoted scalar", "single quoted scalar"
  if (reason.includes("quoted scalar")) {
    const quoteChar = reason.includes("double") ? '"' : "'";
    for (let i = lastLine; i >= 0; i--) {
      const count = lines[i].split(quoteChar).length - 1;
      if (count % 2 !== 0) return i;
    }
  }

  // Colon / mapping errors — covers missing colon AND unclosed quotes that
  // masquerade as colon errors (js-yaml consumes lines into the string,
  // then reports "colon is missed" or "implicit mapping" at a later line).
  if (
    reason.includes("document separator") ||
    reason.includes("bad indentation") ||
    reason.includes("implicit key") ||
    reason.includes("implicit mapping") ||
    reason.includes("colon is missed")
  ) {
    // First check: unclosed quote before the error line (masked quote error)
    const searchTo = Math.min(line, lastLine);
    for (let i = searchTo; i >= 0; i--) {
      for (const q of ['"', "'"]) {
        const count = lines[i].split(q).length - 1;
        if (count % 2 !== 0) return i;
      }
    }

    // No unclosed quote — walk backwards to find a bare key missing its colon
    for (let i = searchTo - 1; i >= 0; i--) {
      const trimmed = lines[i].trim();
      if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
      if (!trimmed.includes(":")) return i;
      break;
    }
    // Fallback: one line back if in range
    if (line > 0) return line - 1;
  }

  return line;
}

/**
 * Create a structured error object.
 */
function err(message, line) {
  return { message, line: line ?? null, severity: "error" };
}

/**
 * Create a structured warning object.
 */
function warn(message, line) {
  return { message, line: line ?? null, severity: "warning" };
}

/**
 * Levenshtein distance between two strings.
 * Used to suggest corrections for misspelled keys.
 */
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }

  return dp[m][n];
}

/**
 * Find the closest match from a Set of valid keys.
 * Returns the suggestion if distance <= 2, otherwise null.
 */
function suggestKey(input, validKeys) {
  let best = null;
  let bestDist = 3;

  for (const key of validKeys) {
    const dist = levenshtein(input.toLowerCase(), key.toLowerCase());
    if (dist < bestDist) {
      bestDist = dist;
      best = key;
    }
  }

  return best;
}

/**
 * Parse a YAML string into a validated, template-expanded config.
 *
 * Returns:
 *   { config, variables, errors, warnings }
 *   - config: expanded config object (null if parsing failed)
 *   - variables: resolved variables map
 *   - errors: fatal parse/validation errors
 *   - warnings: non-fatal issues (unknown keys, undefined vars)
 */
export function parseConfig(yamlString) {
  const errors = [];
  const warnings = [];

  if (!yamlString || !yamlString.trim()) {
    return { config: null, variables: {}, errors: [err("Empty configuration")], warnings };
  }

  let raw;
  try {
    raw = jsyaml.load(yamlString);
  } catch (e) {
    let line = e.mark ? e.mark.line : null;
    const lastLine = yamlString.split("\n").length - 1;
    // Clamp to valid line range — js-yaml sometimes reports past EOF
    if (line !== null && line > lastLine) line = lastLine;
    // Adjust line to point at the actual cause, not the detection point
    line = adjustSyntaxErrorLine(line, e.reason, yamlString);
    return {
      config: null,
      variables: {},
      errors: [err(`YAML syntax error: ${e.message}`, line)],
      warnings,
    };
  }

  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return {
      config: null,
      variables: {},
      errors: [err("Configuration must be a YAML mapping (object)")],
      warnings,
    };
  }

  // Warn on unknown top-level keys with typo suggestions
  for (const key of Object.keys(raw)) {
    if (!VALID_TOP_KEYS.has(key)) {
      const line = findKeyLine(yamlString, key);
      const suggestion = suggestKey(key, VALID_TOP_KEYS);
      if (suggestion) {
        warnings.push(warn(`Unknown top-level key '${key}' — did you mean '${suggestion}'?`, line));
      } else {
        warnings.push(warn(`Unknown top-level key: '${key}'`, line));
      }
    }
  }

  // Validate variables block
  if (raw.variables !== undefined && (typeof raw.variables !== "object" || Array.isArray(raw.variables))) {
    errors.push(err("'variables' must be a mapping", findKeyLine(yamlString, "variables")));
  }

  // Validate zones block
  if (raw.zones !== undefined) {
    if (typeof raw.zones !== "object" || Array.isArray(raw.zones)) {
      errors.push(err("'zones' must be a mapping of zone names to zone configs", findKeyLine(yamlString, "zones")));
    } else {
      for (const [zoneName, zone] of Object.entries(raw.zones)) {
        if (typeof zone !== "object" || Array.isArray(zone) || zone === null) {
          errors.push(err(`Zone '${zoneName}' must be a mapping`, findKeyLine(yamlString, zoneName, "zones")));
          continue;
        }
        for (const key of Object.keys(zone)) {
          if (!VALID_ZONE_KEYS.has(key)) {
            const line = findKeyLine(yamlString, key, zoneName);
            const suggestion = suggestKey(key, VALID_ZONE_KEYS);
            if (suggestion) {
              warnings.push(warn(`Zone '${zoneName}': unknown key '${key}' — did you mean '${suggestion}'?`, line));
            } else {
              warnings.push(warn(`Zone '${zoneName}': unknown key '${key}'`, line));
            }
          }
        }
        validateZone(zoneName, zone, yamlString, errors, warnings);
      }
    }
  }

  // Validate direct block
  if (raw.direct !== undefined) {
    if (typeof raw.direct !== "object" || Array.isArray(raw.direct) || raw.direct === null) {
      errors.push(err("'direct' must be a mapping", findKeyLine(yamlString, "direct")));
    } else {
      for (const key of Object.keys(raw.direct)) {
        if (!VALID_DIRECT_KEYS.has(key)) {
          const line = findKeyLine(yamlString, key, "direct");
          const suggestion = suggestKey(key, VALID_DIRECT_KEYS);
          if (suggestion) {
            warnings.push(warn(`Direct: unknown key '${key}' — did you mean '${suggestion}'?`, line));
          } else {
            warnings.push(warn(`Direct: unknown key '${key}'`, line));
          }
        }
      }
      validateDirect(raw.direct, yamlString, errors, warnings);
    }
  }

  if (errors.length > 0) {
    return { config: null, variables: {}, errors, warnings };
  }

  // Process templates (variable substitution + loop expansion)
  const { config, variables, warnings: templateWarnings } = processTemplate(raw);
  for (const tw of templateWarnings) {
    warnings.push(typeof tw === "string" ? warn(tw) : tw);
  }

  return { config, variables, errors: [], warnings };
}

/**
 * Warn on unknown keys in a nested object.
 * @param {string} context - label for warnings (e.g., "Zone 'public' port")
 * @param {object} obj - object to check
 * @param {Set} validKeys - allowed keys
 * @param {string} yamlString - raw YAML for line lookup
 * @param {string} parentKey - parent key for scoped line search
 * @param {object[]} warnings - collector
 */
function warnUnknownKeys(context, obj, validKeys, yamlString, parentKey, warnings) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return;
  for (const key of Object.keys(obj)) {
    if (!validKeys.has(key)) {
      const line = findKeyLine(yamlString, key, parentKey);
      const suggestion = suggestKey(key, validKeys);
      if (suggestion) {
        warnings.push(warn(`${context}: unknown key '${key}' — did you mean '${suggestion}'?`, line));
      } else {
        warnings.push(warn(`${context}: unknown key '${key}'`, line));
      }
    }
  }
}

function validateZone(name, zone, yamlString, errors, warnings) {
  const ctx = `Zone '${name}'`;

  if (zone.target !== undefined) {
    const targetStr = String(zone.target);
    if (!VALID_TARGETS.includes(targetStr)) {
      const line = findKeyLine(yamlString, "target", name);
      warnings.push(warn(`${ctx}: target '${targetStr}' is not one of ${VALID_TARGETS.join(", ")}`, line));
    }
  }

  const arrayFields = [
    "interfaces", "sources", "services", "ports", "protocols",
    "source_ports", "rich_rules", "forward_ports", "icmp_blocks",
  ];

  for (const field of arrayFields) {
    if (zone[field] !== undefined && !Array.isArray(zone[field])) {
      errors.push(err(`${ctx}: '${field}' must be an array`, findKeyLine(yamlString, field, name)));
    }
  }

  // Validate port entries
  if (Array.isArray(zone.ports)) {
    for (const p of zone.ports) {
      if (p !== null && typeof p === "object" && !Array.isArray(p)) {
        warnUnknownKeys(`${ctx} port`, p, VALID_PORT_KEYS, yamlString, "ports", warnings);
        if (p.port === undefined) {
          warnings.push(warn(`${ctx}: port entry missing 'port' field`, findKeyLine(yamlString, "ports", name)));
        }
      }
    }
  }

  // Validate source_ports entries
  if (Array.isArray(zone.source_ports)) {
    for (const sp of zone.source_ports) {
      if (sp !== null && typeof sp === "object" && !Array.isArray(sp)) {
        warnUnknownKeys(`${ctx} source_port`, sp, VALID_PORT_KEYS, yamlString, "source_ports", warnings);
        if (sp.port === undefined) {
          warnings.push(warn(`${ctx}: source_port entry missing 'port' field`, findKeyLine(yamlString, "source_ports", name)));
        }
      }
    }
  }

  // Validate forward_ports entries
  if (Array.isArray(zone.forward_ports)) {
    for (const fp of zone.forward_ports) {
      if (fp !== null && typeof fp === "object" && !Array.isArray(fp)) {
        warnUnknownKeys(`${ctx} forward_port`, fp, VALID_FORWARD_PORT_KEYS, yamlString, "forward_ports", warnings);
        if (fp.port === undefined) {
          warnings.push(warn(`${ctx}: forward_port entry missing 'port' field`, findKeyLine(yamlString, "forward_ports", name)));
        }
      }
    }
  }

  // Validate rich_rules entries
  if (Array.isArray(zone.rich_rules)) {
    for (const rule of zone.rich_rules) {
      if (rule !== null && typeof rule === "object" && !Array.isArray(rule)) {
        warnUnknownKeys(`${ctx} rich_rule`, rule, VALID_RICH_RULE_KEYS, yamlString, "rich_rules", warnings);
        if (!rule.action && !rule.log && !rule.audit && !rule.masquerade) {
          warnings.push(warn(`${ctx}: rich_rule has no action, log, audit, or masquerade`, findKeyLine(yamlString, "rich_rules", name)));
        }
      }
    }
  }
}

function validateDirect(direct, yamlString, errors, warnings) {
  // Chains
  if (direct.chains !== undefined) {
    if (!Array.isArray(direct.chains)) {
      errors.push(err("'direct.chains' must be an array", findKeyLine(yamlString, "chains", "direct")));
    } else {
      for (const chain of direct.chains) {
        if (chain !== null && typeof chain === "object") {
          warnUnknownKeys("Direct chain", chain, VALID_DIRECT_CHAIN_KEYS, yamlString, "chains", warnings);
          if (!chain.ipv || !chain.table || !chain.chain) {
            warnings.push(warn("Direct chain entry missing required fields (ipv, table, chain)", findKeyLine(yamlString, "chains", "direct")));
          }
        }
      }
    }
  }

  // Rules
  if (direct.rules !== undefined) {
    if (!Array.isArray(direct.rules)) {
      errors.push(err("'direct.rules' must be an array", findKeyLine(yamlString, "rules", "direct")));
    } else {
      for (const rule of direct.rules) {
        if (rule !== null && typeof rule === "object") {
          warnUnknownKeys("Direct rule", rule, VALID_DIRECT_RULE_KEYS, yamlString, "rules", warnings);
          if (!rule.ipv || !rule.table || !rule.chain || rule.priority === undefined || !rule.args) {
            warnings.push(warn("Direct rule entry missing required fields (ipv, table, chain, priority, args)", findKeyLine(yamlString, "rules", "direct")));
          }
        }
      }
    }
  }

  // Passthroughs
  if (direct.passthroughs !== undefined) {
    if (!Array.isArray(direct.passthroughs)) {
      errors.push(err("'direct.passthroughs' must be an array", findKeyLine(yamlString, "passthroughs", "direct")));
    } else {
      for (const pt of direct.passthroughs) {
        if (pt !== null && typeof pt === "object") {
          warnUnknownKeys("Direct passthrough", pt, VALID_PASSTHROUGH_KEYS, yamlString, "passthroughs", warnings);
          if (!pt.ipv || !pt.args) {
            warnings.push(warn("Direct passthrough entry missing required fields (ipv, args)", findKeyLine(yamlString, "passthroughs", "direct")));
          }
        }
      }
    }
  }

  // Rule groups
  if (direct.rule_groups !== undefined) {
    if (!Array.isArray(direct.rule_groups)) {
      errors.push(err("'direct.rule_groups' must be an array", findKeyLine(yamlString, "rule_groups", "direct")));
    } else {
      for (const group of direct.rule_groups) {
        if (group !== null && typeof group === "object") {
          warnUnknownKeys("Direct rule_group", group, VALID_RULE_GROUP_KEYS, yamlString, "rule_groups", warnings);
          if (!group.ipv) {
            warnings.push(warn("Direct rule_group missing 'ipv' field", findKeyLine(yamlString, "rule_groups", "direct")));
          }
          if (!group.table) {
            warnings.push(warn("Direct rule_group missing 'table' field", findKeyLine(yamlString, "rule_groups", "direct")));
          }
          if (!group.chain) {
            warnings.push(warn("Direct rule_group missing 'chain' field", findKeyLine(yamlString, "rule_groups", "direct")));
          }
          // Validate nested rules within group
          if (group.rules !== undefined && Array.isArray(group.rules)) {
            for (const rule of group.rules) {
              if (rule !== null && typeof rule === "object") {
                warnUnknownKeys("Direct rule_group rule", rule, VALID_RULE_GROUP_RULE_KEYS, yamlString, "rules", warnings);
                if (rule.priority === undefined) {
                  warnings.push(warn("Direct rule_group rule missing 'priority' field", findKeyLine(yamlString, "rules", "rule_groups")));
                }
                if (!rule.args) {
                  warnings.push(warn("Direct rule_group rule missing 'args' field", findKeyLine(yamlString, "rules", "rule_groups")));
                }
              }
            }
          }
        }
      }
    }
  }
}
