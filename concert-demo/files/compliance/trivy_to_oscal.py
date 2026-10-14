#!/usr/bin/env python3
"""Convert a Trivy Kubernetes compliance report to the OSCAL Concert reads as compliance_posture.

Input is the JSON of `trivy k8s --compliance k8s-cis-1.23 --report all --format json`.
Concert ships a converter of its own (scanner_name=trivy), but it takes the environment
from a OpenShift style target ("pod/...com") and answers "No_Target_Name" for k3s. This
script writes the same OSCAL structure with the Concert environment name as the host, so
the posture lands on the environment. Concert maps each observation (idref = Trivy check
id such as AVD-KCV-0048) to the controls of the profile through the component definition
of the CIS catalog.

Runs on the demo VMs (Ubuntu 22.04, Python 3.10): standard library only.
"""
import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _now():
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


_CHECK_ID = re.compile(r"^(KSV|KCV)-?0*(\d+)$")


def _check_id(misconfiguration):
    """Concert maps checks as AVD-KSV-0001 / AVD-KCV-0048. Trivy 0.75 reports "KSV-0001" and
    no AVDID, older versions "KSV001" or "KCV0048"; anything unknown is passed on as it is."""
    raw = misconfiguration.get("AVDID") or misconfiguration.get("ID") or ""
    match = _CHECK_ID.match(raw)
    if match:
        return "AVD-{}-{:04d}".format(match.group(1), int(match.group(2)))
    return raw


def _observations(report, inventory_uuid, now):
    """One observation per check id; Trivy repeats a check under every control that uses it."""
    seen = set()
    observations = []
    for control in report.get("Results") or []:
        for target in control.get("Results") or []:
            for misconfiguration in target.get("Misconfigurations") or []:
                check_id = _check_id(misconfiguration)
                if not check_id or check_id in seen:
                    continue
                seen.add(check_id)
                observations.append({
                    "uuid": str(uuid.uuid4()),
                    "description": misconfiguration.get("Title", ""),
                    "props": [
                        {"name": "idref", "value": check_id},
                        {"name": "result", "value": str(misconfiguration.get("Status", "")).lower()},
                        {"name": "time", "value": now},
                        {"name": "severity", "value": misconfiguration.get("Severity", "")},
                    ],
                    "methods": ["TEST-AUTOMATED"],
                    "subjects": [{"subject-uuid": inventory_uuid, "type": "inventory-item"}],
                    "collected": now,
                })
    return observations


def convert(report, hostname, now=None):
    """Return the OSCAL document for a Trivy compliance report; raise ValueError when unusable."""
    if not hostname:
        raise ValueError("hostname is required: it must be the Concert environment name")
    now = now or _now()
    component_uuid, inventory_uuid, validator_uuid, platform_uuid = (str(uuid.uuid4()) for _ in range(4))
    observations = _observations(report, inventory_uuid, now)
    if not observations:
        raise ValueError("the Trivy report holds no misconfiguration results")

    related = report.get("RelatedResources") or [""]
    return {
        "results": [{
            "uuid": str(uuid.uuid4()),
            "title": "trivyscan-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            "description": "Trivy Scan Results",
            "start": report.get("StartedTimeStamp") or now,
            "end": report.get("EndedTimeStamp") or now,
            "local-definitions": {
                "components": [{
                    "uuid": component_uuid,
                    "type": "Service",
                    "title": "Trivy",
                    "description": "Trivy",
                    "status": {"state": "operational"},
                }],
                "inventory-items": [{
                    "uuid": inventory_uuid,
                    "description": "inventory",
                    "props": [
                        {"name": "target", "value": hostname},
                        {"name": "target_type", "value": "trivy"},
                        {"name": "host_name", "value": hostname},
                    ],
                    "implemented-components": [{"component-uuid": component_uuid}],
                }],
                "assessment-assets": {
                    "components": [{
                        "uuid": validator_uuid,
                        "type": "Validator",
                        "title": "Trivy",
                        "description": "Trivy",
                        "props": [
                            {"name": "scanner_name", "value": "Trivy"},
                            {"name": "version", "value": report.get("Version", "unknown")},
                            {"name": "benchmark_id", "value": report.get("ID", "k8s-cis-1.23")},
                            {"name": "benchmark_href", "value": related[0]},
                            {"name": "id", "value": report.get("ID", "trivy_result")},
                        ],
                        "status": {"state": "operational"},
                    }],
                    "assessment-platforms": [{"uuid": platform_uuid}],
                },
            },
            "reviewed-controls": {"control-selections": [{}]},
            "observations": observations,
        }]
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--trivy", required=True, help="Trivy compliance report (JSON)")
    parser.add_argument("--hostname", required=True, help="Concert environment name")
    parser.add_argument("--out", required=True, help="OSCAL file to write")
    args = parser.parse_args(argv)

    with open(args.trivy, encoding="utf-8") as handle:
        report = json.load(handle)
    try:
        document = convert(report, hostname=args.hostname)
    except ValueError as error:
        print("trivy_to_oscal: " + str(error), file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
    print("{} observations for {}".format(len(document["results"][0]["observations"]), args.hostname))
    return 0


if __name__ == "__main__":
    sys.exit(main())
