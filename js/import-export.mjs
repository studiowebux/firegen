// Pattern: Command — import/export actions encapsulated as functions

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
