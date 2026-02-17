// Pattern: Mediator — orchestrates editor, parser, generator, tabs, and import/export

import { initEditor } from "./editor.mjs";
import { parseConfig } from "./parser.mjs";
import { generateApply, generateRemove } from "./generator.mjs";
import { initTabs, setTabContent, getActiveTabContent, setOutputTheme } from "./tabs.mjs";
import { exportYaml, setupImport } from "./import-export.mjs";
import { SAMPLE_YAML } from "./sample.mjs";

function init() {
  const editorContainer = document.getElementById("editor-container");
  const errorBar = document.getElementById("editor-errors");
  const themeToggle = document.getElementById("theme-toggle");
  const btnExample = document.getElementById("btn-example");
  const btnImport = document.getElementById("btn-import");
  const btnExport = document.getElementById("btn-export");
  const btnCopy = document.getElementById("btn-copy");
  const fileImport = document.getElementById("file-import");

  // Initialize tabs (must happen before editor so output CodeMirrors exist)
  initTabs({
    onTabChange() {
      // No additional action needed; tabs handle their own refresh
    },
  });

  // Initialize YAML editor
  const editor = initEditor(editorContainer, {
    value: SAMPLE_YAML,
    onChange: handleYamlChange,
  });

  // Process the initial sample
  handleYamlChange(SAMPLE_YAML);

  // Theme toggle
  themeToggle.addEventListener("click", () => {
    const html = document.documentElement;
    const isDark = html.getAttribute("data-theme") === "dark";
    const newTheme = isDark ? "light" : "dark";
    html.setAttribute("data-theme", newTheme);
    editor.setTheme(newTheme === "dark");
    setOutputTheme(newTheme === "dark");
  });

  // Load example
  btnExample.addEventListener("click", () => {
    editor.setValue(SAMPLE_YAML);
  });

  // Import
  btnImport.addEventListener("click", () => {
    fileImport.click();
  });

  setupImport(fileImport, (content) => {
    editor.setValue(content);
  });

  // Export
  btnExport.addEventListener("click", () => {
    const yaml = editor.getValue();
    exportYaml(yaml);
  });

  // Copy active tab
  btnCopy.addEventListener("click", () => {
    const content = getActiveTabContent();
    navigator.clipboard.writeText(content).then(() => {
      const original = btnCopy.textContent;
      btnCopy.textContent = "Copied";
      setTimeout(() => {
        btnCopy.textContent = original;
      }, 1500);
    });
  });

  /**
   * Handle YAML editor content changes.
   * Parse, expand templates, generate commands, update output tabs.
   */
  function handleYamlChange(yamlString) {
    const { config, errors, warnings } = parseConfig(yamlString);

    // Display errors
    if (errors.length > 0) {
      errorBar.textContent = errors.join("\n");
      errorBar.hidden = false;
      setTabContent("apply", "# Errors in configuration — fix YAML to generate commands");
      setTabContent("remove", "# Errors in configuration — fix YAML to generate commands");
      return;
    }

    // Display warnings inline as comments
    let warningHeader = "";
    if (warnings.length > 0) {
      warningHeader = warnings.map((w) => `# WARNING: ${w}`).join("\n") + "\n\n";
      errorBar.textContent = warnings.join("\n");
      errorBar.hidden = false;
    } else {
      errorBar.hidden = true;
    }

    // Generate commands
    const applyLines = generateApply(config);
    const removeLines = generateRemove(config);

    setTabContent("apply", warningHeader + applyLines.join("\n"));
    setTabContent("remove", warningHeader + removeLines.join("\n"));
  }
}

document.addEventListener("DOMContentLoaded", init);
