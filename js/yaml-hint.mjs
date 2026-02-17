// Pattern: Strategy — context-aware autocomplete for YAML firewalld configs

import {
  VALID_TOP_KEYS, VALID_ZONE_KEYS, VALID_PORT_KEYS, VALID_FORWARD_PORT_KEYS,
  VALID_RICH_RULE_KEYS, VALID_DIRECT_KEYS, VALID_DIRECT_RULE_KEYS,
  VALID_DIRECT_CHAIN_KEYS, VALID_PASSTHROUGH_KEYS, VALID_RULE_GROUP_KEYS,
  VALID_RULE_GROUP_RULE_KEYS, VALID_TARGETS,
} from "./schema.mjs";

/**
 * Get the effective indentation of a YAML line.
 * For array items (`- key: val`), the key's effective indent is after the `- `.
 */
function getLineIndent(text) {
  const rawIndent = text.search(/\S/);
  if (rawIndent < 0) return { raw: -1, effective: -1, isArrayItem: false };

  const trimmed = text.trimStart();
  const isArrayItem = trimmed.startsWith("- ");

  return {
    raw: rawIndent,
    effective: isArrayItem ? rawIndent + 2 : rawIndent,
    isArrayItem,
  };
}

/**
 * Extract the YAML key name from a line, stripping array prefix if present.
 * Returns null if line has no key.
 */
function extractKey(text) {
  const trimmed = text.trimStart().replace(/^-\s*/, "");
  const match = trimmed.match(/^([\w_]+)\s*:/);
  return match ? match[1] : null;
}

/**
 * Walk up from the cursor line to build a context chain of ancestor keys.
 * Returns { ancestors: string[], currentIndent: number }
 *
 * ancestors[0] = immediate parent key, ancestors[1] = grandparent, etc.
 */
function getYamlContext(cm) {
  const cursor = cm.getCursor();
  const lineText = cm.getLine(cursor.line);
  const { effective: currentIndent } = getLineIndent(lineText);

  // Handle empty line: use cursor column as hint for intended indent
  const effectiveCurrent = currentIndent >= 0 ? currentIndent : cursor.ch;

  if (effectiveCurrent <= 0) {
    return { ancestors: [], currentIndent: 0 };
  }

  const ancestors = [];
  let searchBelow = effectiveCurrent;

  for (let i = cursor.line - 1; i >= 0; i--) {
    const text = cm.getLine(i);
    const { raw, effective } = getLineIndent(text);

    // Skip blank lines and comments
    if (raw < 0 || text.trimStart().startsWith("#")) continue;

    // This line must have strictly less effective indentation than what we're searching for
    if (effective < searchBelow) {
      const key = extractKey(text);
      if (key) {
        ancestors.push(key);
        searchBelow = raw < effective ? raw : effective;

        // We only need parent + grandparent + great-grandparent at most
        if (ancestors.length >= 3) break;
        if (searchBelow <= 0) break;
      }
    }
  }

  return { ancestors, currentIndent: effectiveCurrent };
}

/**
 * Map YAML context to the appropriate set of valid keys.
 */
function getKeysForContext(ancestors) {
  const parent = ancestors[0] || null;
  const grandparent = ancestors[1] || null;

  // Top level
  if (parent === null) {
    return VALID_TOP_KEYS;
  }

  // Under zones > <zone_name> — suggest zone keys
  if (grandparent === "zones" && parent !== "zones") {
    return VALID_ZONE_KEYS;
  }

  // Zone array fields
  if (parentIsZoneArrayField(parent, ancestors)) {
    if (parent === "ports" || parent === "source_ports") return VALID_PORT_KEYS;
    if (parent === "forward_ports") return VALID_FORWARD_PORT_KEYS;
    if (parent === "rich_rules") return VALID_RICH_RULE_KEYS;
  }

  // Direct block
  if (parent === "direct") {
    return VALID_DIRECT_KEYS;
  }

  // Direct arrays — disambiguate `rules` via grandparent
  if (parent === "rules") {
    if (grandparent === "direct") return VALID_DIRECT_RULE_KEYS;
    // rules inside a rule_group entry
    return VALID_RULE_GROUP_RULE_KEYS;
  }
  if (parent === "chains") return VALID_DIRECT_CHAIN_KEYS;
  if (parent === "passthroughs") return VALID_PASSTHROUGH_KEYS;
  if (parent === "rule_groups") return VALID_RULE_GROUP_KEYS;

  // Under zones — zone names are user-defined
  if (parent === "zones") return null;
  // Under variables — variable names are user-defined
  if (parent === "variables") return null;

  return null;
}

/**
 * Check if parent is a zone array field by verifying the ancestor chain
 * leads back through a zone name to `zones`.
 */
function parentIsZoneArrayField(parent, ancestors) {
  const zoneArrayFields = ["ports", "source_ports", "forward_ports", "rich_rules", "icmp_blocks", "protocols", "interfaces", "sources", "services"];
  if (!zoneArrayFields.includes(parent)) return false;

  // grandparent should be a zone name, great-grandparent should be `zones`
  return ancestors[2] === "zones" || ancestors[1] === "zones";
}

/**
 * Extract partial word at cursor (the key being typed).
 */
function getPartialWord(cm) {
  const cursor = cm.getCursor();
  const lineText = cm.getLine(cursor.line);
  const beforeCursor = lineText.slice(0, cursor.ch);

  // Match the partial key name at end (after indent and optional `- `)
  const match = beforeCursor.match(/([\w_]*)$/);
  const word = match ? match[1] : "";
  const start = cursor.ch - word.length;

  return { word, start };
}

/**
 * Extract variable names from the editor content.
 */
function extractVariableNames(cm) {
  const names = [];
  let inVariables = false;
  let variablesIndent = -1;

  for (let i = 0; i < cm.lineCount(); i++) {
    const text = cm.getLine(i);
    const trimmed = text.trimStart();

    if (trimmed.match(/^variables\s*:/)) {
      inVariables = true;
      variablesIndent = text.search(/\S/);
      continue;
    }

    if (inVariables) {
      const indent = text.search(/\S/);
      if (indent >= 0 && indent <= variablesIndent && trimmed && !trimmed.startsWith("#")) {
        break;
      }
      const varMatch = trimmed.match(/^([\w_]+)\s*:/);
      if (varMatch && indent > variablesIndent) {
        names.push(varMatch[1]);
      }
    }
  }

  return names;
}

/**
 * Check if cursor is in a variable reference context (inside {{ }}).
 */
function getVariableContext(cm) {
  const cursor = cm.getCursor();
  const lineText = cm.getLine(cursor.line);
  const beforeCursor = lineText.slice(0, cursor.ch);

  const match = beforeCursor.match(/\{\{\s*([\w_]*)$/);
  if (match) {
    return { partial: match[1], start: cursor.ch - match[1].length };
  }

  return null;
}

/**
 * Check if cursor is at a value position for target or boolean suggestions.
 */
function getValueContext(cm) {
  const cursor = cm.getCursor();
  const lineText = cm.getLine(cursor.line);
  const beforeCursor = lineText.slice(0, cursor.ch);

  // target: <value>
  const targetMatch = beforeCursor.match(/^\s*target\s*:\s*([\w]*)$/);
  if (targetMatch) {
    return { type: "target", partial: targetMatch[1], start: cursor.ch - targetMatch[1].length };
  }

  // forward: <bool> or masquerade: <bool>
  const boolMatch = beforeCursor.match(/^\s*(forward|masquerade|icmp_block_inversion)\s*:\s*([\w]*)$/);
  if (boolMatch) {
    return { type: "boolean", partial: boolMatch[2], start: cursor.ch - boolMatch[2].length };
  }

  // family: <value>
  const familyMatch = beforeCursor.match(/^\s*family\s*:\s*([\w]*)$/);
  if (familyMatch) {
    return { type: "family", partial: familyMatch[1], start: cursor.ch - familyMatch[1].length };
  }

  // action: <value>
  const actionMatch = beforeCursor.match(/^\s*action\s*:\s*([\w]*)$/);
  if (actionMatch) {
    return { type: "action", partial: actionMatch[1], start: cursor.ch - actionMatch[1].length };
  }

  // protocol: <value>
  const protoMatch = beforeCursor.match(/^\s*protocol\s*:\s*([\w]*)$/);
  if (protoMatch) {
    return { type: "protocol", partial: protoMatch[1], start: cursor.ch - protoMatch[1].length };
  }

  // ipv: <value>
  const ipvMatch = beforeCursor.match(/^\s*ipv\s*:\s*([\w]*)$/);
  if (ipvMatch) {
    return { type: "ipv", partial: ipvMatch[1], start: cursor.ch - ipvMatch[1].length };
  }

  return null;
}

const VALUE_OPTIONS = {
  target: VALID_TARGETS,
  boolean: ["true", "false"],
  family: ["ipv4", "ipv6"],
  action: ["accept", "reject", "drop", "mark"],
  protocol: ["tcp", "udp", "sctp", "dccp"],
  ipv: ["ipv4", "ipv6"],
};

/**
 * CM5 hint function for YAML firewalld configs.
 */
function yamlHint(cm) {
  const cursor = cm.getCursor();

  // 1. Variable reference context
  const varCtx = getVariableContext(cm);
  if (varCtx) {
    const varNames = extractVariableNames(cm);
    const builtins = ["item", "ipv_any"];
    const all = [...varNames, ...builtins];
    const filtered = all.filter((v) => v.startsWith(varCtx.partial));

    if (filtered.length === 0) return null;

    return {
      list: filtered.map((v) => ({
        text: v + " }}",
        displayText: "{{ " + v + " }}",
      })),
      from: CodeMirror.Pos(cursor.line, varCtx.start),
      to: cursor,
    };
  }

  // 2. Value context (target, boolean, family, action, protocol, ipv)
  const valCtx = getValueContext(cm);
  if (valCtx) {
    const options = VALUE_OPTIONS[valCtx.type] || [];
    const filtered = options.filter((v) =>
      v.toLowerCase().startsWith(valCtx.partial.toLowerCase()),
    );

    if (filtered.length === 0) return null;

    return {
      list: filtered,
      from: CodeMirror.Pos(cursor.line, valCtx.start),
      to: cursor,
    };
  }

  // 3. Key autocomplete based on YAML context
  const { ancestors } = getYamlContext(cm);
  const keys = getKeysForContext(ancestors);

  if (!keys) return null;

  const { word, start } = getPartialWord(cm);

  const filtered = [...keys].filter((k) =>
    k.toLowerCase().startsWith(word.toLowerCase()),
  );

  if (filtered.length === 0) return null;

  return {
    list: filtered.map((k) => ({
      text: k + ": ",
      displayText: k,
    })),
    from: CodeMirror.Pos(cursor.line, start),
    to: cursor,
  };
}

/**
 * Register the YAML hint helper with CodeMirror.
 */
export function registerYamlHint() {
  CodeMirror.registerHelper("hint", "yaml", yamlHint);
}
