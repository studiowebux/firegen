// Pattern: Adapter — wraps CodeMirror 5 global into a module interface

let editorInstance = null;

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
    placeholder: "# Enter your firewalld YAML configuration here...",
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
