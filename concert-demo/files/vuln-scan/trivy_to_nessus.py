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
import re
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


# datetime.fromisoformat only takes 3 or 6 fractional digits before Python 3.11 (Ubuntu
# 22.04 has 3.10) but Trivy emits any length, so split the timestamp up ourselves.
_ISO_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)


def _epoch(iso):
    """Epoch seconds as string; None if absent or unparsable (a bad date must not abort the scan)."""
    if not iso:
        return None
    match = _ISO_TIMESTAMP.match(iso.strip())
    if not match:
        return None
    base, offset = match.groups()
    parsed = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
    shift = 0
    if offset and offset != "Z":
        sign = -1 if offset[0] == "-" else 1
        digits = offset[1:].replace(":", "")
        shift = sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
    return str(int(parsed.replace(tzinfo=timezone.utc).timestamp()) - shift)


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


def _rank(vuln):
    """Higher is worse; used to pick the entry that represents a CVE."""
    score = _v3_score(vuln.get("CVSS"))
    return score if score is not None else -1.0


def _merge(entries, vulns):
    """Fold the per-package entries of one CVE into one: worst entry wins, packages are
    listed, and the solution comes from a package that has a fix."""
    worst_index = max(range(len(vulns)), key=lambda i: (_rank(vulns[i]), -i))
    merged = dict(entries[worst_index])
    merged["pluginName"] = ", ".join(e["pluginName"] for e in entries)
    fixed = next((e for e, v in zip(entries, vulns) if v.get("FixedVersion")), None)
    if fixed:
        merged["solution"] = fixed["solution"]
    return merged


def convert(trivy, hostname, ip, os_name, now=None):
    """Return the Nessus-format list for one host: one entry per CVE.

    Concert's Nessus mapper has no package field and merges findings per CVE, so
    folding the per-package rows here loses nothing and keeps the upload small.
    """
    if not hostname:
        raise ValueError("hostname is required: it must equal the Concert host reference_id")
    now = int(time.time()) if now is None else now
    per_cve = {}  # insertion-ordered: first appearance of a CVE fixes its position
    seen = set()
    for result in trivy.get("Results", []):
        family = result.get("Class", "os-pkgs")
        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID", "")
            key = (cve, vuln.get("PkgName"))
            if not cve.startswith("CVE-") or key in seen:
                continue
            seen.add(key)
            entries, vulns = per_cve.setdefault(cve, ([], []))
            entries.append(_entry(vuln, hostname, ip, os_name, family, now))
            vulns.append(vuln)
    return [_merge(entries, vulns) for entries, vulns in per_cve.values()]


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
