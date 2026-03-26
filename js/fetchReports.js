/**
 * Fetch all three vulnerability report JSON files.
 * Returns an array of parsed JSON objects.
 */
export async function fetchReports() {
  const reports = [
    "openmrs-core.json",
    "openmrs-module-addresshierarchy.json",
    "openmrs-module-attachments.json",
    "openmrs-module-authentication.json",
    "openmrs-module-bedmanagement.json",
    "openmrs-module-billing.json",
    "openmrs-module-calculation.json",
    "openmrs-module-cohort.json",
    "openmrs-module-emrapi.json",
    "openmrs-module-event.json",
    "openmrs-module-fhir2.json",
    "openmrs-module-htmlwidgets.json",
    "openmrs-module-idgen.json",
    "openmrs-module-legacyui.json",
    "openmrs-module-metadatamapping.json",
    "openmrs-module-o3forms.json",
    "openmrs-module-openconceptlab.json",
    "openmrs-module-ordertemplates.json",
    "openmrs-module-patientdocuments.json",
    "openmrs-module-patientflags.json",
    "openmrs-module-queue.json",
    "openmrs-module-referencedemodata.json",
    "openmrs-module-reportingrest.json",
    "openmrs-module-serialization.xstream.json",
    "openmrs-module-stockmanagement.json",
    "openmrs-module-webservices.rest.json",
    "openmrs-esm-patient-chart.json",
    "openmrs-esm-patient-management.json"
  ];

  const responses = await Promise.all(
    reports.map((report) => fetch(`data/${report}`).then((r) => r.json())),
  );

  return responses;
}
