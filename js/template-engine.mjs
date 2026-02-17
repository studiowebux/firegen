// Pattern: Template Method — variable substitution and loop expansion

const VAR_PATTERN = /\{\{\s*(\w+)\s*\}\}/g;
const ITEM_PATTERN = /\{\{\s*item\s*\}\}/g;

/**
 * Extract the variables block from a parsed YAML config.
 * Returns a flat map of variable names to their values (scalar or array).
 */
export function extractVariables(config) {
  if (!config || typeof config.variables !== "object") {
    return {};
  }
  return { ...config.variables };
}

/**
 * Substitute {{ variable_name }} references in a string with scalar values.
 * Returns { result, warnings } where warnings lists undefined variable names.
 */
export function substituteScalars(str, variables) {
  const warnings = [];
  if (typeof str !== "string") {
    return { result: str, warnings };
  }

  const result = str.replace(VAR_PATTERN, (match, name) => {
    if (name === "item") {
      return match; // Preserve {{ item }} for loop expansion
    }
    if (!(name in variables)) {
      warnings.push(name);
      return match;
    }
    const val = variables[name];
    if (Array.isArray(val)) {
      return match; // Array variables are resolved via loop, not inline
    }
    return String(val);
  });

  return { result, warnings };
}

/**
 * Resolve one level of variable-to-variable references.
 * e.g. if var_a references {{ var_b }}, resolve var_a's value.
 */
export function resolveVariables(variables) {
  const resolved = {};
  for (const [key, value] of Object.entries(variables)) {
    if (typeof value === "string") {
      const { result } = substituteScalars(value, variables);
      resolved[key] = result;
    } else if (Array.isArray(value)) {
      resolved[key] = value.map((item) => {
        if (typeof item === "string") {
          const { result } = substituteScalars(item, variables);
          return result;
        }
        return item;
      });
    } else {
      resolved[key] = value;
    }
  }
  return resolved;
}

/**
 * Substitute all {{ var }} references in an object tree (deep walk).
 * Scalars only — loops are handled separately.
 */
export function substituteObject(obj, variables) {
  const warnings = [];

  function walk(node) {
    if (typeof node === "string") {
      const { result, warnings: w } = substituteScalars(node, variables);
      warnings.push(...w);
      return result;
    }
    if (Array.isArray(node)) {
      return node.map(walk);
    }
    if (node !== null && typeof node === "object") {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        out[k] = walk(v);
      }
      return out;
    }
    return node;
  }

  return { result: walk(obj), warnings };
}

/**
 * Expand loop directives in an array of objects.
 * Any object with a `loop: "{{ array_name }}"` key is duplicated
 * for each item in the referenced array, with {{ item }} replaced.
 *
 * Returns { result: expandedArray, warnings: string[] }
 */
export function expandLoops(items, variables) {
  if (!Array.isArray(items)) {
    return { result: items, warnings: [] };
  }

  const expanded = [];
  const warnings = [];

  for (const item of items) {
    if (item !== null && typeof item === "object" && !Array.isArray(item) && item.loop) {
      const loopRef = item.loop;
      const match = loopRef.match(/\{\{\s*(\w+)\s*\}\}/);
      if (!match) {
        warnings.push(`Invalid loop reference: ${loopRef}`);
        expanded.push(item);
        continue;
      }

      const arrayName = match[1];
      const loopValues = variables[arrayName];

      if (!Array.isArray(loopValues)) {
        warnings.push(`Loop variable '${arrayName}' is not an array`);
        expanded.push(item);
        continue;
      }

      for (const loopValue of loopValues) {
        const copy = { ...item };
        delete copy.loop;

        // Replace {{ item }} in all string values
        for (const [k, v] of Object.entries(copy)) {
          if (typeof v === "string") {
            copy[k] = v.replace(ITEM_PATTERN, String(loopValue));
          }
        }
        expanded.push(copy);
      }
    } else {
      expanded.push(item);
    }
  }

  return { result: expanded, warnings };
}

const IPV_ANY_PATTERN = /\{\{\s*ipv_any\s*\}\}/g;
const IPV_ANY_MAP = { ipv4: "0.0.0.0/0", ipv6: "::/0" };

/**
 * Expand rule_groups into flat chains, rules, and passthroughs arrays.
 * Handles ipv: [ipv4, ipv6] by duplicating the group for each version.
 * Replaces {{ ipv_any }} with the version-specific wildcard address.
 */
function expandRuleGroups(direct) {
  if (!direct || !Array.isArray(direct.rule_groups)) {
    return;
  }

  if (!direct.chains) {
    direct.chains = [];
  }
  if (!direct.rules) {
    direct.rules = [];
  }
  if (!direct.passthroughs) {
    direct.passthroughs = [];
  }

  for (const group of direct.rule_groups) {
    const ipvList = Array.isArray(group.ipv) ? group.ipv : [group.ipv];
    const { table, chain } = group;

    for (const ipv of ipvList) {
      const anyAddr = IPV_ANY_MAP[ipv] || "0.0.0.0/0";

      // Add chain
      direct.chains.push({ ipv, table, chain });

      // Expand rules with inherited fields
      if (Array.isArray(group.rules)) {
        for (const rule of group.rules) {
          const expanded = {
            ipv,
            table,
            chain,
            priority: rule.priority,
            args: typeof rule.args === "string" ? rule.args.replace(IPV_ANY_PATTERN, anyAddr) : rule.args,
          };
          if (rule.loop) {
            expanded.loop = rule.loop;
          }
          direct.rules.push(expanded);
        }
      }

      // Expand passthroughs with inherited fields
      if (Array.isArray(group.passthroughs)) {
        for (const pt of group.passthroughs) {
          const expanded = {
            ipv,
            args: typeof pt.args === "string" ? pt.args.replace(IPV_ANY_PATTERN, anyAddr) : pt.args,
          };
          if (pt.loop) {
            expanded.loop = pt.loop;
          }
          direct.passthroughs.push(expanded);
        }
      }
    }
  }

  delete direct.rule_groups;
}

/**
 * Full template processing pipeline:
 * 1. Extract variables
 * 2. Resolve variable-to-variable references
 * 3. Expand rule_groups into flat arrays
 * 4. Substitute scalars throughout config
 * 5. Expand loops in all array fields
 */
export function processTemplate(config) {
  const allWarnings = [];

  const rawVars = extractVariables(config);
  const variables = resolveVariables(rawVars);

  // Deep clone config without the variables block
  const output = JSON.parse(JSON.stringify(config));
  delete output.variables;

  // Expand rule_groups before variable/loop processing
  if (output.direct) {
    expandRuleGroups(output.direct);
  }

  // Substitute scalars in zones
  if (output.zones && typeof output.zones === "object") {
    for (const [zoneName, zone] of Object.entries(output.zones)) {
      for (const [key, value] of Object.entries(zone)) {
        if (Array.isArray(value)) {
          const { result: loopExpanded, warnings: lw } = expandLoops(value, variables);
          allWarnings.push(...lw);
          const { result: substituted, warnings: sw } = substituteObject(loopExpanded, variables);
          allWarnings.push(...sw);
          output.zones[zoneName][key] = substituted;
        } else if (typeof value === "string") {
          const { result, warnings } = substituteScalars(value, variables);
          allWarnings.push(...warnings);
          output.zones[zoneName][key] = result;
        }
      }
    }
  }

  // Substitute scalars and expand loops in direct rules
  if (output.direct && typeof output.direct === "object") {
    for (const [key, value] of Object.entries(output.direct)) {
      if (Array.isArray(value)) {
        const { result: loopExpanded, warnings: lw } = expandLoops(value, variables);
        allWarnings.push(...lw);
        const { result: substituted, warnings: sw } = substituteObject(loopExpanded, variables);
        allWarnings.push(...sw);
        output.direct[key] = substituted;
      }
    }
  }

  return { config: output, variables, warnings: [...new Set(allWarnings)] };
}
