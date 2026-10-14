"""Tests for trivy_to_oscal: Trivy `k8s --compliance` JSON -> Concert compliance_posture (OSCAL)."""
import unittest

from trivy_to_oscal import convert

TRIVY = {
    "ID": "k8s-cis-1.23",
    "Title": "CIS Kubernetes Benchmarks v1.23",
    "Version": "0.57.0",
    "RelatedResources": ["https://www.cisecurity.org/benchmark/kubernetes"],
    "Results": [
        {
            "ID": "1.1.1",
            "Name": "Ensure that the API server pod specification file permissions are set to 600",
            "Severity": "HIGH",
            "Results": [
                {
                    "Target": "Node/worker-1",
                    "Misconfigurations": [
                        {"ID": "KCV0048", "AVDID": "AVD-KCV-0048", "Title": "permissions", "Status": "FAIL", "Severity": "HIGH"},
                        {"ID": "KCV0049", "AVDID": "AVD-KCV-0049", "Title": "ownership", "Status": "PASS", "Severity": "HIGH"},
                    ],
                }
            ],
        },
        {
            # same check reported under a second control -> one observation only
            "ID": "1.1.2",
            "Results": [
                {"Target": "Node/worker-1", "Misconfigurations": [{"ID": "KCV0048", "AVDID": "AVD-KCV-0048", "Title": "permissions", "Status": "FAIL", "Severity": "HIGH"}]}
            ],
        },
        {"ID": "1.1.3", "Results": None},
        {"ID": "1.1.4"},
    ],
}


class TrivyToOscalTest(unittest.TestCase):
    def setUp(self):
        self.doc = convert(TRIVY, hostname="robotshop-prod-ab12", now="2026-10-14T13:00:00Z")
        self.result = self.doc["results"][0]
        self.props = {p["name"]: p["value"] for p in self.result["local-definitions"]["inventory-items"][0]["props"]}
        self.validator = self.result["local-definitions"]["assessment-assets"]["components"][0]

    def test_host_is_the_concert_environment_name(self):
        self.assertEqual(self.props["host_name"], "robotshop-prod-ab12")
        self.assertEqual(self.props["target"], "robotshop-prod-ab12")

    def test_benchmark_id_comes_from_the_report(self):
        values = {p["name"]: p["value"] for p in self.validator["props"]}
        self.assertEqual(values["benchmark_id"], "k8s-cis-1.23")
        self.assertEqual(values["scanner_name"], "Trivy")
        self.assertEqual(values["version"], "0.57.0")

    def test_one_observation_per_check_with_lower_case_result(self):
        obs = {o["props"][0]["value"]: o for o in self.result["observations"]}
        self.assertEqual(sorted(obs), ["AVD-KCV-0048", "AVD-KCV-0049"])
        results = {k: next(p["value"] for p in v["props"] if p["name"] == "result") for k, v in obs.items()}
        self.assertEqual(results, {"AVD-KCV-0048": "fail", "AVD-KCV-0049": "pass"})

    def test_observations_point_at_the_inventory_item(self):
        inventory_uuid = self.result["local-definitions"]["inventory-items"][0]["uuid"]
        for o in self.result["observations"]:
            self.assertEqual(o["subjects"][0]["subject-uuid"], inventory_uuid)

    def test_times_use_the_given_clock(self):
        self.assertEqual(self.result["observations"][0]["collected"], "2026-10-14T13:00:00Z")
        self.assertEqual(self.result["start"], "2026-10-14T13:00:00Z")

    def test_check_ids_without_avd_prefix_are_normalised(self):
        # Trivy 0.75 reports ID "KSV-0001" and no AVDID; Concert maps "AVD-KSV-0001".
        report = {"ID": "k8s-cis-1.23", "Results": [{"ID": "5.1.1", "Results": [{"Target": "Pod/x", "Misconfigurations": [
            {"ID": "KSV-0001", "Title": "t", "Status": "FAIL"},
            {"ID": "KSV001", "Title": "old style", "Status": "FAIL"},
            {"ID": "KCV0048", "Title": "kubelet", "Status": "PASS"},
            {"ID": "AVD-KSV-0017", "Title": "has prefix", "Status": "FAIL"},
            {"ID": "SOMETHING-ELSE", "Title": "unknown family", "Status": "FAIL"},
        ]}]}]}
        doc = convert(report, hostname="h", now="2026-10-14T13:00:00Z")
        ids = sorted(o["props"][0]["value"] for o in doc["results"][0]["observations"])
        self.assertEqual(ids, ["AVD-KCV-0048", "AVD-KSV-0001", "AVD-KSV-0017", "SOMETHING-ELSE"])

    def test_empty_hostname_is_rejected(self):
        with self.assertRaises(ValueError):
            convert(TRIVY, hostname="")

    def test_report_without_misconfigurations_is_rejected(self):
        with self.assertRaises(ValueError):
            convert({"ID": "k8s-cis-1.23", "Results": []}, hostname="h")


if __name__ == "__main__":
    unittest.main()
