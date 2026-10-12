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


class PublishedDateTest(unittest.TestCase):
    """Trivy emits fractional seconds of any length; Ubuntu 22.04 ships Python 3.10
    whose datetime.fromisoformat only accepts 3 or 6 digits (live failure 2026-10-12)."""

    @staticmethod
    def _pub(date):
        vuln = {"VulnerabilityID": "CVE-2022-0001", "PkgName": "x", "Severity": "LOW", "PublishedDate": date}
        out = convert({"Results": [{"Class": "os-pkgs", "Vulnerabilities": [vuln]}]},
                      hostname="h", ip="", os_name="x", now=1)
        return out[0]["vulnPubDate"]

    def test_one_digit_fraction_with_offset(self):
        self.assertEqual(self._pub("2022-03-26T13:15:07.9+00:00"), "1648300507")

    def test_one_digit_fraction_with_z(self):
        self.assertEqual(self._pub("2022-03-26T13:15:07.9Z"), "1648300507")

    def test_nanosecond_fraction(self):
        self.assertEqual(self._pub("2022-03-26T13:15:07.123456789Z"), "1648300507")

    def test_no_fraction(self):
        self.assertEqual(self._pub("2022-03-26T13:15:07Z"), "1648300507")

    def test_non_utc_offset_is_converted(self):
        self.assertEqual(self._pub("2022-03-26T15:15:07+02:00"), "1648300507")

    def test_garbage_date_does_not_abort_the_scan(self):
        self.assertIsNone(self._pub("not-a-date"))


class MergePerCveTest(unittest.TestCase):
    """Concert merges findings per CVE anyway (the Nessus mapper has no package field), and
    22,814 entries for 5,151 CVEs made its scan processing run for over 15 minutes.
    One entry per CVE is lossless for Concert and keeps the upload small."""

    VULNS = [
        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "libssl3", "InstalledVersion": "3.0.1", "FixedVersion": "3.0.2",
         "Severity": "MEDIUM", "CVSS": {"nvd": {"V3Score": 5.5}}},
        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1", "FixedVersion": "3.0.2",
         "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 7.5}}},
        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "libssl-dev", "InstalledVersion": "3.0.1",
         "Severity": "MEDIUM"},
        {"VulnerabilityID": "CVE-2024-0002", "PkgName": "curl", "InstalledVersion": "7.0", "Severity": "LOW"},
    ]

    def setUp(self):
        trivy = {"Results": [{"Class": "os-pkgs", "Vulnerabilities": self.VULNS}]}
        self.out = convert(trivy, hostname="h", ip="", os_name="x", now=1)
        self.by_cve = {e["cve"]: e for e in self.out}

    def test_one_entry_per_cve(self):
        self.assertEqual(sorted(self.by_cve), ["CVE-2024-0001", "CVE-2024-0002"])
        self.assertEqual(len(self.out), 2)

    def test_keeps_the_highest_cvss_and_matching_severity(self):
        entry = self.by_cve["CVE-2024-0001"]
        self.assertEqual(entry["cvssV3BaseScore"], 7.5)
        self.assertEqual(entry["severity"], {"name": "High"})

    def test_lists_all_affected_packages(self):
        self.assertEqual(self.by_cve["CVE-2024-0001"]["pluginName"], "libssl3, openssl, libssl-dev")

    def test_solution_comes_from_a_package_that_has_a_fix(self):
        self.assertIn("3.0.2", self.by_cve["CVE-2024-0001"]["solution"])

    def test_order_follows_first_appearance(self):
        self.assertEqual([e["cve"] for e in self.out], ["CVE-2024-0001", "CVE-2024-0002"])


if __name__ == "__main__":
    unittest.main()
