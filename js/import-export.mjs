// Pattern: Command — import/export actions encapsulated as functions

import { parseCommands } from "./reverse-parser.mjs";

/**
 * Deduplicate an array using a key function.
 * Preserves order, keeps first occurrence.
 */
function dedup(arr, keyFn) {
  const seen = new Set();
  return arr.filter((item) => {
    const key = keyFn(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Key function for port objects ({ port, protocol }) or plain strings.
 */
function portKey(p) {
  if (typeof p === "object" && p !== null) {
    return `${p.port}/${p.protocol || "tcp"}`;
  }
  return String(p);
}

/**
 * Key function for forward-port objects.
 */
function forwardPortKey(fp) {
  return `${fp.port}/${fp.protocol || "tcp"}/${fp.to_port || ""}/${fp.to_addr || ""}`;
}

/**
 * Key function for string values or objects with a .value property.
 */
function stringKey(v) {
  return typeof v === "object" && v !== null ? String(v.value) : String(v);
}

/**
 * Serialize a rich rule object to a comparable string.
 */
function richRuleKey(rule) {
  return JSON.stringify(rule);
}

/**
 * Merge two zone objects. Arrays are concatenated and deduplicated.
 * Scalar values (target, forward, masquerade) from incoming overwrite existing.
 */
function mergeZone(existing, incoming) {
  const merged = { ...existing };

  // Scalars: incoming wins
  if (incoming.target !== undefined) merged.target = incoming.target;
  if (incoming.forward !== undefined) merged.forward = incoming.forward;
  if (incoming.masquerade !== undefined) merged.masquerade = incoming.masquerade;
  if (incoming.icmp_block_inversion !== undefined) merged.icmp_block_inversion = incoming.icmp_block_inversion;

  // Array fields with their dedup key functions
  const arrayFields = [
    ["interfaces", stringKey],
    ["sources", stringKey],
    ["services", stringKey],
    ["ports", portKey],
    ["protocols", stringKey],
    ["source_ports", portKey],
    ["rich_rules", richRuleKey],
    ["forward_ports", forwardPortKey],
    ["icmp_blocks", stringKey],
  ];

  for (const [field, keyFn] of arrayFields) {
    const a = existing[field] || [];
    const b = incoming[field] || [];
    if (a.length > 0 || b.length > 0) {
      merged[field] = dedup([...a, ...b], keyFn);
    }
  }

  return merged;
}

/**
 * Merge two direct blocks. Arrays are concatenated and deduplicated.
 */
function mergeDirect(existing, incoming) {
  const merged = {};

  const chainKey = (c) => `${c.ipv}|${c.table}|${c.chain}`;
  const ruleKey = (r) => `${r.ipv}|${r.table}|${r.chain}|${r.priority}|${r.args}`;
  const ptKey = (p) => `${p.ipv}|${p.args}`;

  const eChains = existing.chains || [];
  const iChains = incoming.chains || [];
  if (eChains.length > 0 || iChains.length > 0) {
    merged.chains = dedup([...eChains, ...iChains], chainKey);
  }

  const eRules = existing.rules || [];
  const iRules = incoming.rules || [];
  if (eRules.length > 0 || iRules.length > 0) {
    merged.rules = dedup([...eRules, ...iRules], ruleKey);
  }

  const ePt = existing.passthroughs || [];
  const iPt = incoming.passthroughs || [];
  if (ePt.length > 0 || iPt.length > 0) {
    merged.passthroughs = dedup([...ePt, ...iPt], ptKey);
  }

  // Preserve rule_groups from existing (import never produces them)
  if (existing.rule_groups) {
    merged.rule_groups = existing.rule_groups;
  }

  return merged;
}

/**
 * Deep-merge two firewalld config objects.
 * Zones are merged per-zone. Direct blocks are merged.
 * Top-level keys from existing that aren't in incoming are preserved (e.g., variables).
 */
export function mergeConfigs(existing, incoming) {
  const merged = { ...existing };

  // Merge zones
  if (incoming.zones) {
    if (!merged.zones) merged.zones = {};
    for (const [name, zone] of Object.entries(incoming.zones)) {
      if (merged.zones[name]) {
        merged.zones[name] = mergeZone(merged.zones[name], zone);
      } else {
        merged.zones[name] = zone;
      }
    }
  }

  // Merge direct
  if (incoming.direct) {
    if (merged.direct) {
      merged.direct = mergeDirect(merged.direct, incoming.direct);
    } else {
      merged.direct = incoming.direct;
    }
  }

  return merged;
}

/**
 * Download a string as a .yaml file.
 * @param {string} content - YAML string to export
 * @param {string} filename - download filename (default: firewalld-config.yaml)
 */
export function exportYaml(content, filename = "firewalld-config.yaml") {
  const blob = new Blob([content], { type: "text/yaml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Set up the import file input to read a .yaml file.
 * @param {HTMLInputElement} fileInput - the hidden file input element
 * @param {function} onLoad - callback(yamlString) when file is loaded
 */
export function setupImport(fileInput, onLoad) {
  fileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target.result;
      onLoad(content);
    };
    reader.readAsText(file);

    // Reset so the same file can be re-imported
    fileInput.value = "";
  });
}

/**
 * Set up the bash import modal flow.
 * @param {object} elements - DOM elements for the modal
 * @param {HTMLButtonElement} elements.btnOpen - button that opens the modal
 * @param {HTMLElement} elements.modal - the modal overlay
 * @param {HTMLTextAreaElement} elements.textarea - the paste textarea
 * @param {HTMLButtonElement} elements.btnImport - the import/submit button
 * @param {HTMLButtonElement} elements.btnCancel - the cancel/close button
 * @param {HTMLElement} elements.status - status message area
 * @param {HTMLInputElement} elements.mergeCheckbox - merge toggle checkbox
 * @param {function} onImport - callback(yamlString) when import succeeds
 * @param {function} getEditorYaml - returns current editor YAML string (for merge mode)
 */
export function setupBashImport(elements, onImport, getEditorYaml) {
  const { btnOpen, modal, textarea, btnImport, btnCancel, status, mergeCheckbox } = elements;

  function openModal() {
    textarea.value = "";
    status.hidden = true;
    status.textContent = "";
    modal.hidden = false;
    textarea.focus();
  }

  function closeModal() {
    modal.hidden = true;
  }

  btnOpen.addEventListener("click", openModal);
  btnCancel.addEventListener("click", closeModal);

  // Close on backdrop click
  modal.addEventListener("click", (e) => {
    if (e.target === modal) {
      closeModal();
    }
  });

  // Close on Escape
  modal.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeModal();
    }
  });

  btnImport.addEventListener("click", () => {
    const text = textarea.value.trim();
    if (!text) {
      return;
    }

    const { config, errors, skipped } = parseCommands(text);

    // Show status with skipped/error counts
    const parts = [];
    if (skipped.length > 0) {
      parts.push(`${skipped.length} skipped`);
    }
    if (errors.length > 0) {
      parts.push(`${errors.length} error${errors.length > 1 ? "s" : ""}`);
    }

    if (parts.length > 0) {
      status.textContent = parts.join(", ") + (errors.length > 0 ? ": " + errors.join("; ") : "");
      status.hidden = false;
    }

    // Only import if we got something
    if (Object.keys(config).length === 0) {
      status.textContent = "No valid firewall-cmd commands found.";
      status.hidden = false;
      return;
    }

    let finalConfig = config;

    // Merge mode: combine with existing editor content
    if (mergeCheckbox && mergeCheckbox.checked && getEditorYaml) {
      const existingYaml = getEditorYaml();
      if (existingYaml && existingYaml.trim()) {
        try {
          const existing = jsyaml.load(existingYaml);
          if (existing && typeof existing === "object" && !Array.isArray(existing)) {
            finalConfig = mergeConfigs(existing, config);
          }
        } catch {
          // Existing YAML is invalid — fall through to replace mode
        }
      }
    }

    const yaml = jsyaml.dump(finalConfig, { lineWidth: -1, noRefs: true });
    onImport(yaml);
    closeModal();
  });
}
