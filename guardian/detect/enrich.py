import importlib.metadata
import json

from cvss import CVSS2, CVSS3, CVSS4

from guardian.detect.risk import vulnerability_severity


def cvss_score(vector):
    parser = (
        CVSS4 if vector.startswith("CVSS:4") else CVSS3 if vector.startswith("CVSS:3") else CVSS2
    )
    return float(parser(vector).scores()[0])


def enrich(vulnerabilities, components, http):
    raw, kev_evidence = http.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    kev = {item["cveID"] for item in json.loads(raw)["vulnerabilities"]}
    index = {c.purl: c for c in components}
    for item in vulnerabilities:
        scores = []
        for vector in item.vectors:
            try:
                scores.append(cvss_score(vector))
            except ValueError:
                continue
        item.cvss_score = max(scores) if scores else None
        if item.vectors:
            calculated = http.recorder.capture(
                json.dumps({"vectors": item.vectors, "base_score": item.cvss_score}).encode(),
                tool="cvss",
                version=importlib.metadata.version("cvss"),
                command=["cvss", "base-score", *item.vectors],
                cwd=http.directory,
                description="CVSS base score computed from advisory vectors",
            )
            item.evidence_ids.append(calculated)
        cves = sorted(a for a in [item.id, *item.aliases] if a.startswith("CVE-"))
        item.kev = any(cve in kev for cve in cves) if cves else None
        item.evidence_ids.append(kev_evidence)
        for cve in cves:
            raw, epss_evidence = http.get("https://api.first.org/data/v1/epss?cve=" + cve)
            rows = json.loads(raw)["data"]
            if rows:
                score = float(rows[0]["epss"])
                if item.epss is None or score > item.epss:
                    item.epss, item.epss_percentile = score, float(rows[0]["percentile"])
            item.evidence_ids.append(epss_evidence)
        item.severity, _ = vulnerability_severity(
            item.cvss_score, item.kev, item.epss, index[item.component].scopes
        )
    return vulnerabilities
