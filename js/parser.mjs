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

const VALID_DIRECT_KEYS = new Set(["chains", "rules", "passthroughs", "rule_groups"]);
const VALID_TOP_KEYS = new Set(["variables", "zones", "direct"]);

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

  // Warn on unknown top-level keys
  for (const key of Object.keys(raw)) {
    if (!VALID_TOP_KEYS.has(key)) {
      warnings.push(`Unknown top-level key: '${key}'`);
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
            warnings.push(`Zone '${zoneName}': unknown key '${key}'`);
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
          warnings.push(`Direct: unknown key '${key}'`);
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

function validateZone(name, zone, errors, warnings) {
  if (zone.target !== undefined) {
    const validTargets = ["default", "ACCEPT", "DROP", "REJECT"];
    const targetStr = String(zone.target);
    if (!validTargets.includes(targetStr)) {
      warnings.push(`Zone '${name}': target '${targetStr}' is not one of ${validTargets.join(", ")}`);
    }
  }

  if (zone.interfaces !== undefined && !Array.isArray(zone.interfaces)) {
    errors.push(`Zone '${name}': 'interfaces' must be an array`);
  }

  if (zone.sources !== undefined && !Array.isArray(zone.sources)) {
    errors.push(`Zone '${name}': 'sources' must be an array`);
  }

  if (zone.services !== undefined && !Array.isArray(zone.services)) {
    errors.push(`Zone '${name}': 'services' must be an array`);
  }

  if (zone.ports !== undefined && !Array.isArray(zone.ports)) {
    errors.push(`Zone '${name}': 'ports' must be an array`);
  }

  if (zone.protocols !== undefined && !Array.isArray(zone.protocols)) {
    errors.push(`Zone '${name}': 'protocols' must be an array`);
  }

  if (zone.source_ports !== undefined && !Array.isArray(zone.source_ports)) {
    errors.push(`Zone '${name}': 'source_ports' must be an array`);
  }

  if (zone.rich_rules !== undefined && !Array.isArray(zone.rich_rules)) {
    errors.push(`Zone '${name}': 'rich_rules' must be an array`);
  }

  if (zone.forward_ports !== undefined && !Array.isArray(zone.forward_ports)) {
    errors.push(`Zone '${name}': 'forward_ports' must be an array`);
  }

  if (zone.icmp_blocks !== undefined && !Array.isArray(zone.icmp_blocks)) {
    errors.push(`Zone '${name}': 'icmp_blocks' must be an array`);
  }
}

function validateDirect(direct, errors, warnings) {
  if (direct.chains !== undefined) {
    if (!Array.isArray(direct.chains)) {
      errors.push("'direct.chains' must be an array");
    } else {
      for (const chain of direct.chains) {
        if (!chain.ipv || !chain.table || !chain.chain) {
          warnings.push("Direct chain entry missing required fields (ipv, table, chain)");
        }
      }
    }
  }

  if (direct.rules !== undefined) {
    if (!Array.isArray(direct.rules)) {
      errors.push("'direct.rules' must be an array");
    } else {
      for (const rule of direct.rules) {
        if (!rule.ipv || !rule.table || !rule.chain || rule.priority === undefined || !rule.args) {
          warnings.push("Direct rule entry missing required fields (ipv, table, chain, priority, args)");
        }
      }
    }
  }

  if (direct.passthroughs !== undefined) {
    if (!Array.isArray(direct.passthroughs)) {
      errors.push("'direct.passthroughs' must be an array");
    } else {
      for (const pt of direct.passthroughs) {
        if (!pt.ipv || !pt.args) {
          warnings.push("Direct passthrough entry missing required fields (ipv, args)");
        }
      }
    }
  }
}
