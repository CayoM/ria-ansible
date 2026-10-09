#!/usr/bin/env python3
"""Convert a Trivy rootfs JSON report into Concert's vm_scan input (Nessus format).

Concert picks the mapper by scanner_name; "nessus" reads a JSON list with
dnsName (= infrastructure component reference_id, i.e. the k8s node name),
cve, severity.name, cvssV3BaseScore, ... (see Concert's nessus.jsonata).

Usage:
  trivy_to_nessus.py --trivy trivy.json --hostname NODE --ip 10.0.0.5 \
      --os-name "RHEL 9" --out vm_scan.json
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone

CVSS_SOURCE_PREFERENCE = ("nvd", "redhat", "ghsa")


def _v3_score(cvss):
    """NVD first, then other preferred sources, then any source with a V3 score."""
    if not cvss:
        return None
    ordered = [s for s in CVSS_SOURCE_PREFERENCE if s in cvss]
    ordered += [s for s in cvss if s not in ordered]
    for source in ordered:
        score = cvss[source].get("V3Score")
        if score is not None:
            return score
    return None


def _epoch(iso):
    if not iso:
        return None
    parsed = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return str(int(parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp()))


def _entry(vuln, hostname, ip, os_name, family, now):
    fixed = vuln.get("FixedVersion")
    package = vuln.get("PkgName", "")
    description = vuln.get("Description") or vuln.get("Title") or ""
    solution = f"Update {package} to {fixed}" if fixed else f"No fix available for {package} yet"
    return {
        "cve": vuln["VulnerabilityID"],
        "dnsName": hostname,
        "ip": ip,
        "family": {"name": family},
        "severity": {"name": vuln.get("Severity", "UNKNOWN").capitalize()},
        "cvssV3BaseScore": _v3_score(vuln.get("CVSS")),
        "description": description,
        "solution": solution,
        "vulnPubDate": _epoch(vuln.get("PublishedDate")),
        "riskFactor": vuln.get("Severity", "UNKNOWN").capitalize(),
        "pluginName": package,
        "port": "0",
        "protocol": "TCP",
        "firstSeen": str(now),
        "lastSeen": str(now),
        "operatingSystem": os_name,
        "hasBeenMitigated": "false",
    }


def convert(trivy, hostname, ip, os_name, now=None):
    """Return the Nessus-format list for one host; deduped per (CVE, package)."""
    if not hostname:
        raise ValueError("hostname is required: it must equal the Concert host reference_id")
    now = int(time.time()) if now is None else now
    seen = set()
    entries = []
    for result in trivy.get("Results", []):
        family = result.get("Class", "os-pkgs")
        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID", "")
            key = (cve, vuln.get("PkgName"))
            if not cve.startswith("CVE-") or key in seen:
                continue
            seen.add(key)
            entries.append(_entry(vuln, hostname, ip, os_name, family, now))
    return entries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--ip", default="")
    parser.add_argument("--os-name", default="")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    with open(args.trivy, encoding="utf-8") as handle:
        trivy = json.load(handle)
    entries = convert(trivy, args.hostname, args.ip, args.os_name)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=1)
    print(f"{len(entries)} CVEs for {args.hostname} -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
