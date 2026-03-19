/**
 * Fetch all three vulnerability report JSON files.
 * Returns an array of parsed JSON objects.
 */
export async function fetchReports() {
  const reports = [
    "data/openmrs-core.json",
    "data/openmrs-module-billing.json",
    "data/openmrs-module-idgen.json",
  ];

  const responses = await Promise.all(
    reports.map((report) => fetch(report).then((r) => r.json())),
  );

  return responses;
}
