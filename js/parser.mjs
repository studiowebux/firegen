// Pattern: Facade — wraps js-yaml parsing with validation and template processing

import { processTemplate } from "./template-engine.mjs";

const VALID_ZONE_KEYS = new Set([
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

const VALID_PORT_KEYS = new Set(["port", "protocol", "loop"]);
const VALID_FORWARD_PORT_KEYS = new Set(["port", "protocol", "to_port", "to_addr", "loop"]);
const VALID_RICH_RULE_KEYS = new Set([
  "family", "source", "source_invert", "destination", "destination_invert",
  "service", "port", "protocol", "icmp_block", "icmp_type", "masquerade",
  "forward_port", "source_port", "log", "audit", "action", "reject_type",
  "mark_set", "loop",
]);
const VALID_DIRECT_RULE_KEYS = new Set(["ipv", "table", "chain", "priority", "args", "loop"]);
const VALID_DIRECT_CHAIN_KEYS = new Set(["ipv", "table", "chain"]);
const VALID_PASSTHROUGH_KEYS = new Set(["ipv", "args", "loop"]);
const VALID_RULE_GROUP_KEYS = new Set(["ipv", "table", "chain", "rules", "passthroughs"]);

const VALID_DIRECT_KEYS = new Set(["chains", "rules", "passthroughs", "rule_groups"]);
const VALID_TOP_KEYS = new Set(["variables", "zones", "direct"]);

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
    return { config: null, variables: {}, errors: ["Empty configuration"], warnings };
  }

  let raw;
  try {
    raw = jsyaml.load(yamlString);
  } catch (e) {
    return {
      config: null,
      variables: {},
      errors: [`YAML syntax error: ${e.message}`],
      warnings,
    };
  }

  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return {
      config: null,
      variables: {},
      errors: ["Configuration must be a YAML mapping (object)"],
      warnings,
    };
  }

  // Warn on unknown top-level keys with typo suggestions
  for (const key of Object.keys(raw)) {
    if (!VALID_TOP_KEYS.has(key)) {
      const suggestion = suggestKey(key, VALID_TOP_KEYS);
      if (suggestion) {
        warnings.push(`Unknown top-level key '${key}' — did you mean '${suggestion}'?`);
      } else {
        warnings.push(`Unknown top-level key: '${key}'`);
      }
    }
  }

  // Validate variables block
  if (raw.variables !== undefined && (typeof raw.variables !== "object" || Array.isArray(raw.variables))) {
    errors.push("'variables' must be a mapping");
  }

  // Validate zones block
  if (raw.zones !== undefined) {
    if (typeof raw.zones !== "object" || Array.isArray(raw.zones)) {
      errors.push("'zones' must be a mapping of zone names to zone configs");
    } else {
      for (const [zoneName, zone] of Object.entries(raw.zones)) {
        if (typeof zone !== "object" || Array.isArray(zone) || zone === null) {
          errors.push(`Zone '${zoneName}' must be a mapping`);
          continue;
        }
        for (const key of Object.keys(zone)) {
          if (!VALID_ZONE_KEYS.has(key)) {
            const suggestion = suggestKey(key, VALID_ZONE_KEYS);
            if (suggestion) {
              warnings.push(`Zone '${zoneName}': unknown key '${key}' — did you mean '${suggestion}'?`);
            } else {
              warnings.push(`Zone '${zoneName}': unknown key '${key}'`);
            }
          }
        }
        validateZone(zoneName, zone, errors, warnings);
      }
    }
  }

  // Validate direct block
  if (raw.direct !== undefined) {
    if (typeof raw.direct !== "object" || Array.isArray(raw.direct) || raw.direct === null) {
      errors.push("'direct' must be a mapping");
    } else {
      for (const key of Object.keys(raw.direct)) {
        if (!VALID_DIRECT_KEYS.has(key)) {
          const suggestion = suggestKey(key, VALID_DIRECT_KEYS);
          if (suggestion) {
            warnings.push(`Direct: unknown key '${key}' — did you mean '${suggestion}'?`);
          } else {
            warnings.push(`Direct: unknown key '${key}'`);
          }
        }
      }
      validateDirect(raw.direct, errors, warnings);
    }
  }

  if (errors.length > 0) {
    return { config: null, variables: {}, errors, warnings };
  }

  // Process templates (variable substitution + loop expansion)
  const { config, variables, warnings: templateWarnings } = processTemplate(raw);
  warnings.push(...templateWarnings);

  return { config, variables, errors: [], warnings };
}

/**
 * Warn on unknown keys in a nested object.
 * @param {string} context - label for warnings (e.g., "Zone 'public' port")
 * @param {object} obj - object to check
 * @param {Set} validKeys - allowed keys
 * @param {string[]} warnings - collector
 */
function warnUnknownKeys(context, obj, validKeys, warnings) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return;
  for (const key of Object.keys(obj)) {
    if (!validKeys.has(key)) {
      const suggestion = suggestKey(key, validKeys);
      if (suggestion) {
        warnings.push(`${context}: unknown key '${key}' — did you mean '${suggestion}'?`);
      } else {
        warnings.push(`${context}: unknown key '${key}'`);
      }
    }
  }
}

function validateZone(name, zone, errors, warnings) {
  const ctx = `Zone '${name}'`;

  if (zone.target !== undefined) {
    const validTargets = ["default", "ACCEPT", "DROP", "REJECT"];
    const targetStr = String(zone.target);
    if (!validTargets.includes(targetStr)) {
      warnings.push(`${ctx}: target '${targetStr}' is not one of ${validTargets.join(", ")}`);
    }
  }

  const arrayFields = [
    "interfaces", "sources", "services", "ports", "protocols",
    "source_ports", "rich_rules", "forward_ports", "icmp_blocks",
  ];

  for (const field of arrayFields) {
    if (zone[field] !== undefined && !Array.isArray(zone[field])) {
      errors.push(`${ctx}: '${field}' must be an array`);
    }
  }

  // Validate port entries
  if (Array.isArray(zone.ports)) {
    for (const p of zone.ports) {
      if (p !== null && typeof p === "object" && !Array.isArray(p)) {
        warnUnknownKeys(`${ctx} port`, p, VALID_PORT_KEYS, warnings);
        if (p.port === undefined) {
          warnings.push(`${ctx}: port entry missing 'port' field`);
        }
      }
    }
  }

  // Validate source_ports entries
  if (Array.isArray(zone.source_ports)) {
    for (const sp of zone.source_ports) {
      if (sp !== null && typeof sp === "object" && !Array.isArray(sp)) {
        warnUnknownKeys(`${ctx} source_port`, sp, VALID_PORT_KEYS, warnings);
        if (sp.port === undefined) {
          warnings.push(`${ctx}: source_port entry missing 'port' field`);
        }
      }
    }
  }

  // Validate forward_ports entries
  if (Array.isArray(zone.forward_ports)) {
    for (const fp of zone.forward_ports) {
      if (fp !== null && typeof fp === "object" && !Array.isArray(fp)) {
        warnUnknownKeys(`${ctx} forward_port`, fp, VALID_FORWARD_PORT_KEYS, warnings);
        if (fp.port === undefined) {
          warnings.push(`${ctx}: forward_port entry missing 'port' field`);
        }
      }
    }
  }

  // Validate rich_rules entries
  if (Array.isArray(zone.rich_rules)) {
    for (const rule of zone.rich_rules) {
      if (rule !== null && typeof rule === "object" && !Array.isArray(rule)) {
        warnUnknownKeys(`${ctx} rich_rule`, rule, VALID_RICH_RULE_KEYS, warnings);
        if (!rule.action && !rule.log && !rule.audit && !rule.masquerade) {
          warnings.push(`${ctx}: rich_rule has no action, log, audit, or masquerade`);
        }
      }
    }
  }
}

function validateDirect(direct, errors, warnings) {
  // Chains
  if (direct.chains !== undefined) {
    if (!Array.isArray(direct.chains)) {
      errors.push("'direct.chains' must be an array");
    } else {
      for (const chain of direct.chains) {
        if (chain !== null && typeof chain === "object") {
          warnUnknownKeys("Direct chain", chain, VALID_DIRECT_CHAIN_KEYS, warnings);
          if (!chain.ipv || !chain.table || !chain.chain) {
            warnings.push("Direct chain entry missing required fields (ipv, table, chain)");
          }
        }
      }
    }
  }

  // Rules
  if (direct.rules !== undefined) {
    if (!Array.isArray(direct.rules)) {
      errors.push("'direct.rules' must be an array");
    } else {
      for (const rule of direct.rules) {
        if (rule !== null && typeof rule === "object") {
          warnUnknownKeys("Direct rule", rule, VALID_DIRECT_RULE_KEYS, warnings);
          if (!rule.ipv || !rule.table || !rule.chain || rule.priority === undefined || !rule.args) {
            warnings.push("Direct rule entry missing required fields (ipv, table, chain, priority, args)");
          }
        }
      }
    }
  }

  // Passthroughs
  if (direct.passthroughs !== undefined) {
    if (!Array.isArray(direct.passthroughs)) {
      errors.push("'direct.passthroughs' must be an array");
    } else {
      for (const pt of direct.passthroughs) {
        if (pt !== null && typeof pt === "object") {
          warnUnknownKeys("Direct passthrough", pt, VALID_PASSTHROUGH_KEYS, warnings);
          if (!pt.ipv || !pt.args) {
            warnings.push("Direct passthrough entry missing required fields (ipv, args)");
          }
        }
      }
    }
  }

  // Rule groups
  if (direct.rule_groups !== undefined) {
    if (!Array.isArray(direct.rule_groups)) {
      errors.push("'direct.rule_groups' must be an array");
    } else {
      for (const group of direct.rule_groups) {
        if (group !== null && typeof group === "object") {
          warnUnknownKeys("Direct rule_group", group, VALID_RULE_GROUP_KEYS, warnings);
          if (!group.ipv) {
            warnings.push("Direct rule_group missing 'ipv' field");
          }
          if (!group.table) {
            warnings.push("Direct rule_group missing 'table' field");
          }
          if (!group.chain) {
            warnings.push("Direct rule_group missing 'chain' field");
          }
          // Validate nested rules within group
          if (group.rules !== undefined && Array.isArray(group.rules)) {
            for (const rule of group.rules) {
              if (rule !== null && typeof rule === "object") {
                const validGroupRuleKeys = new Set(["priority", "args", "loop"]);
                warnUnknownKeys("Direct rule_group rule", rule, validGroupRuleKeys, warnings);
                if (rule.priority === undefined) {
                  warnings.push("Direct rule_group rule missing 'priority' field");
                }
                if (!rule.args) {
                  warnings.push("Direct rule_group rule missing 'args' field");
                }
              }
            }
          }
        }
      }
    }
  }
}
