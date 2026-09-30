# Sample source files

Small, realistic samples of each source format the shipped mappings understand. They describe a
fictional organisation ("Meridian Bank") and are what `secgraph seed-demo` loads.

The CVE identifiers are real and their CVSS data follows the public record, but the EPSS scores and
the abbreviated catalogues here are **illustrative samples**. For real use, load the current NVD, KEV,
EPSS and ATT&CK files with the same mappings.

| File | Mapping | Format |
|---|---|---|
| `assets.csv` | `assets_csv` | asset inventory / CMDB export |
| `identities.csv` | `identities_csv` | directory export |
| `scanner_findings.csv` | `vuln_findings_csv` | vulnerability scanner export |
| `web-portal-01.cdx.json` | `cyclonedx` | CycloneDX SBOM |
| `nvd_cves.json` | `nvd_cve` | NVD CVE API 2.0 |
| `kev.json` | `cisa_kev` | CISA KEV catalogue |
| `epss.csv` | `epss_csv` | FIRST EPSS scores |
| `attack.stix.json` | `attack_stix` | MITRE ATT&CK STIX 2.1 bundle |
| `ocsf_vulnerability_findings.json` | `ocsf_vulnerability_finding` | OCSF class 2002 |
| `ocsf_detections.json` | `ocsf_detection_finding` | OCSF class 2004 |
| `../estate.json` | — (canonical batch) | everything no standard source provides |
