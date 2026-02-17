// Pattern: Adapter — wraps CodeMirror 5 global into a module interface

import { registerYamlHint } from "./yaml-hint.mjs";

let editorInstance = null;

// Register the YAML hint helper once at module load
registerYamlHint();

/**
 * Initialize CodeMirror on the given container element.
 * @param {HTMLElement} container - DOM element to host the editor
 * @param {object} options
 * @param {string} options.value - initial content
 * @param {function} options.onChange - callback(value) on content change
 * @param {number} options.debounceMs - debounce delay for onChange (default 300)
 * @returns {{ getValue, setValue, setTheme }}
 */
export function initEditor(container, { value = "", onChange = null, debounceMs = 300 } = {}) {
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";

  editorInstance = CodeMirror(container, {
    value,
    mode: "yaml",
    theme: isDark ? "monokai" : "default",
    lineNumbers: true,
    lineWrapping: true,
    tabSize: 2,
    indentWithTabs: false,
    indentUnit: 2,
    placeholder: "# Enter your firewalld YAML configuration here...",
    extraKeys: {
      "Ctrl-Space": "autocomplete",
      // Tab inserts spaces instead of tab character
      "Tab": (cm) => {
        if (cm.somethingSelected()) {
          cm.indentSelection("add");
        } else {
          cm.replaceSelection("  ", "end");
        }
      },
    },
  });

  let debounceTimer = null;

  if (onChange) {
    editorInstance.on("change", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        onChange(editorInstance.getValue());
      }, debounceMs);
    });
  }

  // Auto-trigger hints when typing at key positions
  editorInstance.on("inputRead", (cm, change) => {
    if (change.origin !== "+input") return;

    const cursor = cm.getCursor();
    const lineText = cm.getLine(cursor.line);
    const beforeCursor = lineText.slice(0, cursor.ch);

    // Trigger on variable reference: user typed {{ or is typing a var name
    if (beforeCursor.match(/\{\{\s*[\w_]*$/)) {
      cm.showHint({ completeSingle: false });
      return;
    }

    // Trigger after colon+space for value completion (target, protocol, etc.)
    if (beforeCursor.match(/:\s+[\w]*$/) && beforeCursor.match(/^\s*(target|forward|masquerade|icmp_block_inversion|family|action|protocol|ipv)\s*:/)) {
      cm.showHint({ completeSingle: false });
      return;
    }

    // Trigger at key positions: line has only indent + optional `- ` + word chars (no colon)
    if (beforeCursor.match(/^\s*(-\s+)?[\w_]+$/) && !beforeCursor.includes(":")) {
      cm.showHint({ completeSingle: false });
    }
  });

  return {
    getValue() {
      return editorInstance.getValue();
    },
    setValue(val) {
      editorInstance.setValue(val);
    },
    setTheme(dark) {
      editorInstance.setOption("theme", dark ? "monokai" : "default");
    },
    refresh() {
      editorInstance.refresh();
    },
  };
}
