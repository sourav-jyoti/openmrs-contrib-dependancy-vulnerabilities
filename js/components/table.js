import { getSeverityTagColor, escapeHtml } from "../helpers.js";

export function renderProjectAccordion(project) {
  const tagColor = getSeverityTagColor(project.highestSeverity);

  const title = `${escapeHtml(project.projectName)}`;

  // Build the inner content: dependency table with nested CVE accordions
  const innerContent = renderDependencySection(project.dependencies);

  return `
    <cds-accordion-item title-text="${title}" class="project-accordion-item">
      <span slot="title" class="project-title">
        <span class="project-name">${escapeHtml(project.projectName)}</span>
        <cds-tag type="${tagColor}" class="severity-tag" style="padding: 0 0.5rem;">${escapeHtml(project.highestSeverity)}</cds-tag>
      </span>
      ${innerContent}
    </cds-accordion-item>
  `;
}

/**
 * Render the dependency table section.
 * Each dependency row contains an inner accordion for CVE details.
 */
function renderDependencySection(dependencies) {
  if (dependencies.length === 0) {
    return '<p class="no-data">No vulnerable dependencies found.</p>';
  }

  const rows = dependencies
    .map((dep) => {
      const tagColor = getSeverityTagColor(dep.severity);
      const cveTableHtml = renderCVETable(dep.cves);

      return `
        <cds-accordion-item title-text="${escapeHtml(dep.name)}" class="dep-accordion-item">
          <div slot="title" class="dep-row-title">
            <span class="dep-col dep-name">${escapeHtml(dep.name)}</span>
            <span class="dep-col dep-version">${escapeHtml(dep.version)}</span>
            <span class="dep-col"><cds-tag type="${tagColor}" size="sm" style="padding: 0 0.5rem;">${escapeHtml(dep.severity)}</cds-tag></span>
            <span class="dep-col dep-cve-count">${dep.cveCount}</span>
            <span class="dep-col dep-exploit">${escapeHtml(dep.exploit)}</span>
            <span class="dep-col dep-fix">${escapeHtml(dep.fixVersion)}</span>
          </div>
          <div class="cve-details-wrapper">
            ${cveTableHtml}
          </div>
        </cds-accordion-item>
      `;
    })
    .join("");

  return `
    <div class="dep-table-header">
      <span class="dep-col dep-col-name">Dependency</span>
      <span class="dep-col dep-col-version">Version</span>
      <span class="dep-col dep-col-severity">Severity</span>
      <span class="dep-col dep-col-cves">CVEs</span>
      <span class="dep-col dep-col-exploit">Exploit?</span>
      <span class="dep-col dep-col-fix">Fix Version</span>
    </div>
    <cds-accordion alignment="start" class="dep-accordion">
      ${rows}
    </cds-accordion>
  `;
}

/**
 * Render the CVE detail table for a single dependency.
 */
function renderCVETable(cves) {
  if (!cves || cves.length === 0) {
    return '<p class="no-data">No CVE details available.</p>';
  }

  const rows = cves
    .map((cve) => {
      const tagColor = getSeverityTagColor(cve.severity);
      const roundedScore =
        cve.score !== "-" ? Math.round(Number(cve.score) * 1000) / 1000 : "-";
      const scoreDisplay = roundedScore !== "-" ? `${roundedScore}/10` : "-";

      return `
        <cds-table-row >
          <cds-table-cell class="cve-id-cell">${escapeHtml(cve.cveId)}</cds-table-cell>
          <cds-table-cell><cds-tag type="${tagColor}" size="sm" style="padding: 0 0.5rem;">${escapeHtml(cve.severity)}</cds-tag></cds-table-cell>
          <cds-table-cell>${escapeHtml(String(scoreDisplay))}</cds-table-cell>
          <cds-table-cell>${escapeHtml(cve.description)}</cds-table-cell>
          <cds-table-cell>${escapeHtml(cve.affectedVersion)}</cds-table-cell>
          <cds-table-cell>${escapeHtml(cve.fixedIn)}</cds-table-cell>
          <cds-table-cell>${escapeHtml(cve.cwe)}</cds-table-cell>
        </cds-table-row>
      `;
    })
    .join("");

  return `
    <cds-table class="cve-table" >
      <cds-table-head>
        <cds-table-header-row>
          <cds-table-header-cell>CVE ID</cds-table-header-cell>
          <cds-table-header-cell is-sortable>Severity</cds-table-header-cell>
          <cds-table-header-cell>Score</cds-table-header-cell>
          <cds-table-header-cell>Description</cds-table-header-cell>
          <cds-table-header-cell>Affected Versions</cds-table-header-cell>
          <cds-table-header-cell>Fixed In</cds-table-header-cell>
          <cds-table-header-cell>CWE</cds-table-header-cell>
        </cds-table-header-row>
      </cds-table-head>
      <cds-table-body>
        ${rows}
      </cds-table-body>
    </cds-table>
  `;
}
