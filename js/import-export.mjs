// Pattern: Command — import/export actions encapsulated as functions

import { parseCommands } from "./reverse-parser.mjs";

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
 * @param {function} onImport - callback(yamlString) when import succeeds
 */
export function setupBashImport(elements, onImport) {
  const { btnOpen, modal, textarea, btnImport, btnCancel, status } = elements;

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

    const yaml = jsyaml.dump(config, { lineWidth: -1, noRefs: true });
    onImport(yaml);
    closeModal();
  });
}
