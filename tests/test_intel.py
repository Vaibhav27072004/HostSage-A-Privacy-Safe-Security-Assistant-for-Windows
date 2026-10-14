from __future__ import annotations

import unittest
from unittest import mock

from hids.config import ThreatIntelConfig
from hids.intel import (
    AbuseIPDBProvider,
    ThreatIntelClient,
    VirusTotalProvider,
    classify_risk,
)


class RiskClassificationTests(unittest.TestCase):
    def test_boundaries(self) -> None:
        self.assertEqual(classify_risk(0), "LOW")
        self.assertEqual(classify_risk(39), "LOW")
        self.assertEqual(classify_risk(40), "MEDIUM")
        self.assertEqual(classify_risk(74), "MEDIUM")
        self.assertEqual(classify_risk(75), "HIGH")
        self.assertEqual(classify_risk(100), "HIGH")


class ProviderTests(unittest.TestCase):
    def test_providers_are_disabled_without_a_key(self) -> None:
        for provider in (
            AbuseIPDBProvider("", 5, 1),
            VirusTotalProvider("   ", 5, 1),
        ):
            self.assertFalse(provider.enabled)
            record = provider.lookup("45.33.32.156")
            self.assertEqual(record.risk_score, 0)
            self.assertIn("not configured", record.summary)

    def test_abuseipdb_maps_confidence_score(self) -> None:
        payload = {"data": {"abuseConfidenceScore": 88, "totalReports": 12, "countryCode": "NL"}}
        provider = AbuseIPDBProvider("key", 5, 0)
        with mock.patch("hids.intel._fetch_json", return_value=payload):
            record = provider.lookup("45.33.32.156")
        self.assertEqual(record.risk_score, 88)
        self.assertEqual(record.risk_label, "HIGH")
        self.assertIn("reports=12", record.summary)

    def test_virustotal_maps_analysis_stats(self) -> None:
        provider = VirusTotalProvider("key", 5, 0)
        cases = [
            ({"malicious": 3, "suspicious": 0, "harmless": 60}, "HIGH"),
            ({"malicious": 0, "suspicious": 2, "harmless": 60}, "MEDIUM"),
            ({"malicious": 0, "suspicious": 0, "harmless": 60}, "LOW"),
        ]
        for stats, expected_label in cases:
            payload = {"data": {"attributes": {"last_analysis_stats": stats}}}
            with mock.patch("hids.intel._fetch_json", return_value=payload):
                record = provider.lookup("45.33.32.156")
            self.assertEqual(record.risk_label, expected_label, stats)

    def test_lookup_failure_degrades_to_a_neutral_record(self) -> None:
        provider = AbuseIPDBProvider("key", 5, 0)
        with mock.patch("hids.intel._fetch_json", side_effect=RuntimeError("timed out")):
            record = provider.lookup("45.33.32.156")
        self.assertEqual(record.risk_score, 0)
        self.assertIn("lookup failed", record.summary)


class ClientTests(unittest.TestCase):
    def test_private_addresses_are_never_sent_to_a_provider(self) -> None:
        client = ThreatIntelClient(ThreatIntelConfig(abuseipdb_api_key="key"))
        with mock.patch("hids.intel._fetch_json", side_effect=AssertionError("must not be called")):
            record = client.lookup("192.168.1.10")
        self.assertEqual(record.provider, "local")

    def test_disabled_client_reports_disabled_once_and_caches(self) -> None:
        client = ThreatIntelClient(ThreatIntelConfig())
        record = client.lookup("45.33.32.156")
        self.assertEqual(record.provider, "disabled")
        self.assertIs(client.lookup("45.33.32.156"), record)

    def test_highest_scoring_provider_wins(self) -> None:
        client = ThreatIntelClient(
            ThreatIntelConfig(abuseipdb_api_key="a", virustotal_api_key="b")
        )
        abuse_payload = {"data": {"abuseConfidenceScore": 10, "totalReports": 1, "countryCode": "US"}}
        vt_payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}

        with mock.patch("hids.intel._fetch_json", side_effect=[abuse_payload, vt_payload]):
            record = client.lookup("45.33.32.156")

        self.assertEqual(record.provider, "virustotal")
        self.assertEqual(record.risk_label, "HIGH")

    def test_results_are_cached_for_the_configured_ttl(self) -> None:
        client = ThreatIntelClient(ThreatIntelConfig(abuseipdb_api_key="a"))
        payload = {"data": {"abuseConfidenceScore": 50, "totalReports": 2, "countryCode": "US"}}

        with mock.patch("hids.intel._fetch_json", return_value=payload) as fetch:
            client.lookup("45.33.32.156")
            client.lookup("45.33.32.156")

        self.assertEqual(fetch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
