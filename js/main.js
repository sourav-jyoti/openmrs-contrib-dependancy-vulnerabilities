import { fetchReports } from "./fetchReports.js";
import { parseReports } from "./parseReports.js";
import { renderProjectAccordion, renderDependencyRows } from "./components/table.js";
import { SEVERITY_ORDER } from "./helpers.js";

/**
 * Main entry point.
 * Fetches reports, parses them, and renders the dashboard UI.
 */
async function init() {
  const appContainer = document.getElementById("app");

  try {
    // Show loading state
    appContainer.innerHTML =
      '<p class="loading">Loading vulnerability reports…</p>';

    // 1. Fetch
    const rawReports = await fetchReports();

    // 2. Parse
    const projects = parseReports(rawReports);

    // 3. Render
    const accordionItems = projects
      .map((project) => renderProjectAccordion(project))
      .join("");

    appContainer.innerHTML = `
      <div class="dashboard-header">
        <h1 class="dashboard-title">OpenMRS Dependency Vulnerability Report</h1>
        <span class="title-accent"></span>
        <p class="dashboard-subtitle">A summary of known security vulnerabilities detected across OpenMRS modules by automated dependency scanning. Each module lists its vulnerable dependencies, severity levels, and recommended fix versions to help maintainers prioritize upgrades.</p>
      </div>
      <cds-accordion alignment="start" class="project-accordion">
        ${accordionItems}
      </cds-accordion>
    `;

    // 4. Attach delegated sort listener
    setupSortListeners(appContainer, projects);
  } catch (error) {
    console.error("Failed to load vulnerability reports:", error);
    appContainer.innerHTML = `
      <p class="error">Failed to load vulnerability reports. Check the console for details.</p>
    `;
  }
}

/**
 * Attaches a single delegated click listener for column sorting on all dep tables.
 * Handles sorting by "severity" and "cveCount".
 */
function setupSortListeners(container, projects) {
  container.addEventListener("click", (e) => {
    const headerCell = e.target.closest("cds-table-header-cell[data-sort-key]");
    if (!headerCell) return;

    const table = headerCell.closest("cds-table[data-project-id]");
    if (!table) return;

    const projectId = table.dataset.projectId;
    const sortKey = headerCell.dataset.sortKey;

    // Toggle direction: same column flips, new column resets to asc
    const currentKey = table.dataset.sortKey;
    const currentDir = table.dataset.sortDir || "asc";
    const newDir =
      currentKey === sortKey && currentDir === "asc" ? "desc" : "asc";

    table.dataset.sortKey = sortKey;
    table.dataset.sortDir = newDir;

    const project = projects.find(
      (p) => (p.projectName || "").replace(/[^a-zA-Z0-9]/g, "-").toLowerCase() === projectId
    );
    if (!project) return;

    const sorted = [...project.dependencies].sort((a, b) => {
      if (sortKey === "severity") {
        const orderA =
          SEVERITY_ORDER[(a.severity || "").toLowerCase()] ??
          SEVERITY_ORDER["-"];
        const orderB =
          SEVERITY_ORDER[(b.severity || "").toLowerCase()] ??
          SEVERITY_ORDER["-"];
        return newDir === "asc" ? orderA - orderB : orderB - orderA;
      }
      if (sortKey === "cveCount") {
        return newDir === "asc"
          ? a.cveCount - b.cveCount
          : b.cveCount - a.cveCount;
      }
      return 0;
    });

    const tbody = table.querySelector("cds-table-body");
    if (tbody) tbody.innerHTML = renderDependencyRows(sorted);
  });
}

// Run on DOM ready
document.addEventListener("DOMContentLoaded", init);
