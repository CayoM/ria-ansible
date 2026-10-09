"""Tests for trivy_to_nessus: Trivy rootfs JSON -> Concert vm_scan (Nessus format)."""
import unittest

from trivy_to_nessus import convert

TRIVY = {
    "Results": [
        {
            "Target": "host (rhel 9.6)",
            "Class": "os-pkgs",
            "Type": "redhat",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2025-4802",
                    "PkgName": "glibc",
                    "InstalledVersion": "2.34-100",
                    "FixedVersion": "2.34-168",
                    "Severity": "HIGH",
                    "Title": "glibc: static setuid binary dlopen",
                    "Description": "Untrusted LD_LIBRARY_PATH in glibc.",
                    "PublishedDate": "2025-05-16T00:00:00Z",
                    "CVSS": {
                        "redhat": {"V3Score": 6.5},
                        "nvd": {"V3Score": 7.8},
                    },
                },
                # same CVE+package twice (Trivy repeats per Target) -> deduped
                {
                    "VulnerabilityID": "CVE-2025-4802",
                    "PkgName": "glibc",
                    "InstalledVersion": "2.34-100",
                    "Severity": "HIGH",
                },
                # no fix, only a redhat score, no description
                {
                    "VulnerabilityID": "CVE-2026-1111",
                    "PkgName": "openssl-libs",
                    "InstalledVersion": "3.0.7",
                    "Severity": "CRITICAL",
                    "CVSS": {"redhat": {"V3Score": 9.1}},
                },
                # not a CVE id (vendor advisory) -> skipped, Concert keys on CVE
                {"VulnerabilityID": "RHSA-2025:1234", "PkgName": "bash", "Severity": "LOW"},
            ],
        },
        {"Target": "empty", "Class": "os-pkgs"},  # no Vulnerabilities key
    ]
}


class ConvertTest(unittest.TestCase):
    def setUp(self):
        self.out = convert(TRIVY, hostname="node-1", ip="10.0.0.5", os_name="RHEL 9", now=1_790_000_000)

    def test_dedupes_and_skips_non_cve(self):
        self.assertEqual([e["cve"] for e in self.out], ["CVE-2025-4802", "CVE-2026-1111"])

    def test_host_identity_is_dns_name(self):
        for e in self.out:
            self.assertEqual(e["dnsName"], "node-1")
            self.assertEqual(e["ip"], "10.0.0.5")
            self.assertEqual(e["operatingSystem"], "RHEL 9")

    def test_prefers_nvd_v3_score(self):
        self.assertEqual(self.out[0]["cvssV3BaseScore"], 7.8)

    def test_falls_back_to_other_source_score(self):
        self.assertEqual(self.out[1]["cvssV3BaseScore"], 9.1)

    def test_severity_is_capitalised_name(self):
        self.assertEqual(self.out[0]["severity"], {"name": "High"})
        self.assertEqual(self.out[1]["severity"], {"name": "Critical"})

    def test_solution_mentions_fixed_version_only_when_known(self):
        self.assertIn("2.34-168", self.out[0]["solution"])
        self.assertNotIn("None", self.out[1]["solution"])

    def test_publish_date_is_epoch_string(self):
        self.assertEqual(self.out[0]["vulnPubDate"], "1747353600")

    def test_package_goes_into_plugin_name(self):
        self.assertEqual(self.out[0]["pluginName"], "glibc")

    def test_scan_times_are_stringified_epoch(self):
        self.assertEqual(self.out[0]["lastSeen"], "1790000000")

    def test_empty_input_gives_empty_list(self):
        self.assertEqual(convert({}, hostname="h", ip="1.1.1.1", os_name="x", now=1), [])

    def test_requires_hostname(self):
        with self.assertRaises(ValueError):
            convert(TRIVY, hostname="", ip="1.1.1.1", os_name="x", now=1)


if __name__ == "__main__":
    unittest.main()
