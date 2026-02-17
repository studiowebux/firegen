// Pattern: Strategy — context-aware autocomplete for YAML firewalld configs

import {
  VALID_TOP_KEYS, VALID_ZONE_KEYS, VALID_PORT_KEYS, VALID_FORWARD_PORT_KEYS,
  VALID_RICH_RULE_KEYS, VALID_DIRECT_KEYS, VALID_DIRECT_RULE_KEYS,
  VALID_DIRECT_CHAIN_KEYS, VALID_PASSTHROUGH_KEYS, VALID_RULE_GROUP_KEYS,
  VALID_RULE_GROUP_RULE_KEYS, VALID_TARGETS,
} from "./schema.mjs";

/**
 * Walk up from the cursor line to find parent and grandparent YAML keys
 * based on indentation levels.
 *
 * Returns { parentKey, grandparentKey, currentIndent }
 */
function getYamlContext(cm) {
  const cursor = cm.getCursor();
  const lineText = cm.getLine(cursor.line);
  const currentIndent = lineText.search(/\S/);

  // If cursor is at start of file or indent 0, we're at top level
  if (currentIndent <= 0) {
    return { parentKey: null, grandparentKey: null, currentIndent: 0 };
  }

  let parentKey = null;
  let parentIndent = -1;
  let grandparentKey = null;

  // Walk up to find parent (first line with strictly less indentation)
  for (let i = cursor.line - 1; i >= 0; i--) {
    const text = cm.getLine(i);
    const trimmed = text.trimStart();

    // Skip blank lines and comments
    if (!trimmed || trimmed.startsWith("#")) continue;

    const indent = text.search(/\S/);

    // Strip array prefix for indent comparison
    const effectiveIndent = trimmed.startsWith("- ") ? indent + 2 : indent;

    if (indent < currentIndent) {
      // Extract key name from this line
      const keyMatch = trimmed.replace(/^-\s*/, "").match(/^([\w_]+)\s*:/);
      if (keyMatch) {
        if (parentKey === null) {
          parentKey = keyMatch[1];
          parentIndent = indent;
        } else if (grandparentKey === null) {
          grandparentKey = keyMatch[1];
          break;
        }
      } else if (parentKey === null) {
        // Line with less indent but no key (e.g., array scalar) — keep looking
        continue;
      }
    }

    // If we found parent, look for grandparent at even less indentation
    if (parentKey !== null && grandparentKey === null && indent < parentIndent) {
      const keyMatch = trimmed.replace(/^-\s*/, "").match(/^([\w_]+)\s*:/);
      if (keyMatch) {
        grandparentKey = keyMatch[1];
        break;
      }
    }
  }

  return { parentKey, grandparentKey, currentIndent };
}

/**
 * Map YAML context to the appropriate set of valid keys.
 */
function getKeysForContext(parentKey, grandparentKey) {
  // Top level
  if (parentKey === null) {
    return VALID_TOP_KEYS;
  }

  // Under zones > <zone_name> — suggest zone keys
  if (grandparentKey === "zones") {
    return VALID_ZONE_KEYS;
  }

  // Under a zone's array fields
  if (parentKey === "ports" || parentKey === "source_ports") {
    return VALID_PORT_KEYS;
  }
  if (parentKey === "forward_ports") {
    return VALID_FORWARD_PORT_KEYS;
  }
  if (parentKey === "rich_rules") {
    return VALID_RICH_RULE_KEYS;
  }

  // Direct block
  if (parentKey === "direct") {
    return VALID_DIRECT_KEYS;
  }

  // Under direct arrays — disambiguate `rules` via grandparent
  if (parentKey === "rules" && grandparentKey === "direct") {
    return VALID_DIRECT_RULE_KEYS;
  }
  if (parentKey === "rules") {
    // rules inside a rule_group
    return VALID_RULE_GROUP_RULE_KEYS;
  }
  if (parentKey === "chains") {
    return VALID_DIRECT_CHAIN_KEYS;
  }
  if (parentKey === "passthroughs") {
    return VALID_PASSTHROUGH_KEYS;
  }
  if (parentKey === "rule_groups") {
    return VALID_RULE_GROUP_KEYS;
  }

  // Under zones — zone names are user-defined, no suggestions
  if (parentKey === "zones") {
    return null;
  }

  // Under variables — variable names are user-defined
  if (parentKey === "variables") {
    return null;
  }

  return null;
}

/**
 * Extract partial word at cursor (the key being typed).
 */
function getPartialWord(cm) {
  const cursor = cm.getCursor();
  const lineText = cm.getLine(cursor.line);
  const beforeCursor = lineText.slice(0, cursor.ch);

  // Match the partial key name at end of line (after indent and optional `- `)
  const match = beforeCursor.match(/([\w_]*)$/);
  const word = match ? match[1] : "";
  const start = cursor.ch - word.length;

  return { word, start };
}

/**
 * Extract variable names from the editor content.
 * Quick regex scan of the variables block.
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
      // Exited variables block
      if (indent >= 0 && indent <= variablesIndent && trimmed && !trimmed.startsWith("#")) {
        break;
      }
      // Variable name line (direct child of variables)
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

  // Check for {{ at end, possibly with partial variable name
  const match = beforeCursor.match(/\{\{\s*([\w_]*)$/);
  if (match) {
    return { partial: match[1], start: cursor.ch - match[1].length };
  }

  return null;
}

/**
 * Check if cursor is at a value position (after a colon) for target suggestions.
 */
function getTargetContext(cm) {
  const cursor = cm.getCursor();
  const lineText = cm.getLine(cursor.line);
  const beforeCursor = lineText.slice(0, cursor.ch);

  const match = beforeCursor.match(/^\s*target\s*:\s*([\w]*)$/);
  if (match) {
    return { partial: match[1], start: cursor.ch - match[1].length };
  }

  return null;
}

/**
 * CM5 hint function for YAML firewalld configs.
 */
function yamlHint(cm) {
  const cursor = cm.getCursor();

  // Check for variable reference context first
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

  // Check for target value context
  const targetCtx = getTargetContext(cm);
  if (targetCtx) {
    const filtered = VALID_TARGETS.filter((t) =>
      t.toLowerCase().startsWith(targetCtx.partial.toLowerCase()),
    );

    if (filtered.length === 0) return null;

    return {
      list: filtered,
      from: CodeMirror.Pos(cursor.line, targetCtx.start),
      to: cursor,
    };
  }

  // Key autocomplete based on context
  const { parentKey, grandparentKey } = getYamlContext(cm);
  const keys = getKeysForContext(parentKey, grandparentKey);

  if (!keys) return null;

  const { word, start } = getPartialWord(cm);

  // Filter keys by prefix match
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
