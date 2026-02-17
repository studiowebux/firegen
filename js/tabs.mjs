// Pattern: Observer — tab state management with output CodeMirror instances

const outputEditors = {};
let activeTab = "apply";

/**
 * Initialize output tabs and their CodeMirror instances.
 * @param {object} options
 * @param {function} options.onTabChange - callback(tabName) when active tab changes
 */
export function initTabs({ onTabChange = null } = {}) {
  const tabButtons = document.querySelectorAll(".tab-bar .tab");
  const tabContents = document.querySelectorAll(".tab-content");

  // Initialize read-only CodeMirror for each output tab
  for (const content of tabContents) {
    const tabName = content.getAttribute("data-tab");
    const textarea = content.querySelector("textarea");

    if (textarea) {
      const isDark = document.documentElement.getAttribute("data-theme") === "dark";
      const cm = CodeMirror.fromTextArea(textarea, {
        mode: "shell",
        theme: isDark ? "monokai" : "default",
        lineNumbers: true,
        readOnly: true,
        lineWrapping: true,
      });
      outputEditors[tabName] = cm;
    }
  }

  // Tab click handlers
  for (const btn of tabButtons) {
    btn.addEventListener("click", () => {
      const tabName = btn.getAttribute("data-tab");
      activateTab(tabName, tabButtons, tabContents);
      if (onTabChange) {
        onTabChange(tabName);
      }
    });
  }

  // Refresh visible editor after initial render
  requestAnimationFrame(() => {
    if (outputEditors[activeTab]) {
      outputEditors[activeTab].refresh();
    }
  });
}

function activateTab(tabName, tabButtons, tabContents) {
  activeTab = tabName;

  for (const btn of tabButtons) {
    btn.classList.toggle("active", btn.getAttribute("data-tab") === tabName);
  }

  for (const content of tabContents) {
    content.classList.toggle("active", content.getAttribute("data-tab") === tabName);
  }

  // Refresh the newly visible editor
  if (outputEditors[tabName]) {
    requestAnimationFrame(() => {
      outputEditors[tabName].refresh();
    });
  }
}

/**
 * Set the content of an output tab.
 * @param {string} tabName - "apply" or "remove"
 * @param {string} content - text content to display
 */
export function setTabContent(tabName, content) {
  if (outputEditors[tabName]) {
    outputEditors[tabName].setValue(content);
  }
}

/**
 * Get the content of the currently active tab.
 * @returns {string}
 */
export function getActiveTabContent() {
  if (outputEditors[activeTab]) {
    return outputEditors[activeTab].getValue();
  }
  return "";
}

/**
 * Update theme on all output editors.
 * @param {boolean} dark
 */
export function setOutputTheme(dark) {
  for (const cm of Object.values(outputEditors)) {
    cm.setOption("theme", dark ? "monokai" : "default");
  }
}
