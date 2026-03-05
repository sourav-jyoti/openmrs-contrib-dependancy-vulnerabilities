import {
  extractNameFromPackageId,
  extractVersionFromPackageId,
  getHighestSeverity,
  hasAnyExploit,
  getFirstFixVersion,
  getAffectedVersion,
  getFixVersion,
  capitalizeSeverity,
} from "./helpers.js";

export function parseReports(reports) {
  return reports.map((report) => {
    const projectName = report.projectInfo?.name;
    const deps = (report.dependencies || [])
      .filter((dep) => dep.vulnerabilities && dep.vulnerabilities.length > 0)
      .map((dep) => parseDependency(dep));

    // Project-level highest severity
    const allSeverities = deps.map((d) => d.severity);
    const projectSeverity = getHighestFromList(allSeverities);

    return {
      projectName,
      highestSeverity: projectSeverity,
      dependencies: deps,
    };
  });
}

/**
 * Parse a single dependency object.
 */
function parseDependency(dep) {
  const packageId = dep.packages?.[0]?.id || "";
  const name = extractNameFromPackageId(packageId);
  const version = extractVersionFromPackageId(packageId);
  const severity = getHighestSeverity(dep.vulnerabilities);
  const cveCount = dep.vulnerabilities.length;
  const exploit = hasAnyExploit(dep.vulnerabilities);
  const fixVersion = getFirstFixVersion(dep.vulnerabilities);

  const cves = dep.vulnerabilities.map((vuln) => parseCVE(vuln));

  return {
    name,
    version,
    severity,
    cveCount,
    exploit,
    fixVersion,
    cves,
  };
}

/**
 * Parse a single vulnerability / CVE object.
 */
function parseCVE(vuln) {
  return {
    cveId: vuln.name || "-",
    severity: capitalizeSeverity(
      vuln.cvssv3?.baseSeverity || vuln.severity || "-",
    ),
    score: vuln.cvssv3?.baseScore ?? vuln.cvssv2?.score ?? "-",
    description: vuln.description || "-",
    affectedVersion: getAffectedVersion(vuln),
    fixedIn: getFixVersion(vuln),
    cwe: vuln.cwes ? vuln.cwes.join(", ") : "-",
  };
}

/**
 * Get the highest severity from a list of severity strings.
 * Uses a priority cascade: critical → high → medium → low → "-"
 */
function getHighestFromList(severities) {
  const priorities = ["Critical", "High", "Medium", "Low"];

  for (const level of priorities) {
    if (severities.some((s) => s === level)) return level;
  }
  return "-";
}
