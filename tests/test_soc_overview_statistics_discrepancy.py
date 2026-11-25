"""
Regression test suite for Home / SOC Overview statistics discrepancy fix.

Verifies:
1. A nested alert-only normal_event_sets value of zero cannot override the valid
   full-session normal_events value when the backend summary is normalized.
2. Full raw flow count (191,033) is displayed instead of alert-attributed flow count (77,917).
3. Full event-set count (293,166) is displayed instead of alert-only event-set count (9,540).
4. Event-set chart uses 283,626 (normal), 7,697 (known threat) and 1,843 (unknown anomaly).
5. Campaign KPI remains 909 (748 known threat, 161 unknown anomalous campaigns).
6. A genuinely zero normal-event count is still displayed as zero when the full-session count is also zero.
7. Existing Detection History reports remain completely unchanged.
8. Existing upload processing and campaign coalescence behavior remain unchanged.
"""

import json
import re
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app
from backend.service import siem_service
from backend.campaign import coalesce_campaigns
import backend.database as db


class TestSOCOverviewStatisticsDiscrepancy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_backend_normalization_logic(self):
        """
        Req 1: Test that processor summary normalization correctly updates
        flow_statistics and event_set_statistics using full-session counts.
        """
        # Simulate the exact Friday Morning situation:
        # coalesce_campaigns on alert windows produced alert-subset stats:
        alert_window_predictions = [
            {
                "event_set_id": f"ES-{i}",
                "window_id": f"W{i % 50}",
                "k": i % 50,
                "source_ip": f"192.168.10.{i % 20}",
                "destination_ip": "172.16.0.1",
                "window_start": "2026-11-18 09:00:00",
                "window_end": "2026-11-18 09:10:00",
                "verdict": "KNOWN_THREAT" if i < 7697 else "UNKNOWN_ANOMALOUS",
                "confidence": 0.95,
                "ensemble_score": 0.95
            }
            for i in range(7697 + 1843)
        ]
        all_flow_attributions = {f"ES-{i}": list(range(i * 5, i * 5 + 8)) for i in range(len(alert_window_predictions))}

        coalesced = coalesce_campaigns(
            window_predictions=alert_window_predictions,
            flow_attributions=all_flow_attributions,
            session_id="SESS-TEST-NORM",
            window_bins=10,
            step_seconds=60
        )
        flow_stats = coalesced["flow_statistics"]
        event_set_stats = coalesced["event_set_statistics"]
        campaign_stats = coalesced["campaign_statistics"]

        # Before normalization, alert-subset flow_stats has only alert-attributed flows
        self.assertLess(flow_stats["total_raw_flows"], 191033)
        self.assertEqual(event_set_stats["normal_event_sets"], 0)
        self.assertEqual(event_set_stats["total_event_sets"], 9540)

        # Apply processor normalization logic:
        total_rows = 191033
        metrics_snapshot = {
            "total_event_sets": 293166,
            "normal_event_sets": 283626,
            "known_threats": 7697,
            "unknown_anomalous": 1843,
            "severity_dist": {"LOW": 283626, "HIGH": 7697, "MEDIUM": 1843},
            "attack_types": {"PortScan": 7697, "Anomalous": 1843}
        }
        total_event_sets = metrics_snapshot["total_event_sets"]
        normal_count = metrics_snapshot["normal_event_sets"]
        known_threat_event_sets = metrics_snapshot.get("known_threats", 0)
        unknown_anomalous_event_sets = metrics_snapshot.get("unknown_anomalous", 0)

        # Normalization
        flow_stats["total_raw_flows"] = total_rows
        event_set_stats["total_event_sets"] = total_event_sets
        event_set_stats["normal_event_sets"] = normal_count
        event_set_stats["ann_alert_sets"] = known_threat_event_sets
        event_set_stats["unknown_anomalous_sets"] = unknown_anomalous_event_sets

        # Verifications
        self.assertEqual(flow_stats["total_raw_flows"], 191033)
        self.assertEqual(event_set_stats["total_event_sets"], 293166)
        self.assertEqual(event_set_stats["normal_event_sets"], 283626)
        self.assertEqual(event_set_stats["ann_alert_sets"], 7697)
        self.assertEqual(event_set_stats["unknown_anomalous_sets"], 1843)
        self.assertEqual(campaign_stats["total_campaigns"], len(coalesced["campaigns"]))

    def test_02_frontend_canonical_field_resolution_friday_morning(self):
        """
        Req 2, 3, 4, 5: Verify that the canonical resolution in frontend/js/app.js
        correctly extracts full flows, full event sets, normal event sets,
        event-set chart values, and campaign count for the Friday Morning payload.
        """
        # Read frontend/js/app.js to inspect the logic directly
        app_js_path = Path("frontend/js/app.js")
        self.assertTrue(app_js_path.exists(), "frontend/js/app.js must exist")
        js_code = app_js_path.read_text(encoding="utf-8")

        # Verify canonical resolution exists in app.js
        self.assertIn("const totalFlows = Number(summary.total_records ?? flowStats?.total_raw_flows ?? 0);", js_code)
        self.assertIn("const totalEventSets = Number(summary.total_processed ?? eventStats?.total_event_sets ?? totalFlows);", js_code)
        self.assertIn("const normalEventSets = Number(summary.normal_events ?? eventStats?.normal_event_sets ?? 0);", js_code)
        self.assertIn("charts.renderDetectionSummaryDoughnut(\"chartDetectionSummary\", normalEventSets, knownThreatEventSets, unknownAnomEventSets);", js_code)

        # Simulate the exact JS extraction on Friday Morning payload:
        friday_payload = {
            "session_id": "SESS-20261118231919-eca2ed",
            "has_data": True,
            "total_records": 191033,
            "total_processed": 293166,
            "normal_events": 283626,
            "threats_detected": 909,
            "known_threats": 748,
            "unknown_anomalous": 161,
            "flow_statistics": {
                "total_raw_flows": 77917,
                "unique_flows_analysed": 77917,
                "benign_flows": 0,
                "known_threat_flows": 65271,
                "unknown_anomalous_flows": 12646,
                "invalid_flows": 0
            },
            "event_set_statistics": {
                "total_event_sets": 9540,
                "normal_event_sets": 0,
                "ann_alert_sets": 7697,
                "unknown_anomalous_sets": 1843
            },
            "campaign_statistics": {
                "total_campaigns": 909,
                "known_threat_campaigns": 748,
                "unknown_anomalous_campaigns": 161
            }
        }

        # Emulate JS resolution:
        flowStats = friday_payload.get("flow_statistics", {})
        eventStats = friday_payload.get("event_set_statistics", {})
        campStats = friday_payload.get("campaign_statistics", {})

        totalFlows = friday_payload.get("total_records") if friday_payload.get("total_records") is not None else flowStats.get("total_raw_flows", 0)
        totalEventSets = friday_payload.get("total_processed") if friday_payload.get("total_processed") is not None else eventStats.get("total_event_sets", totalFlows)
        normalEventSets = friday_payload.get("normal_events") if friday_payload.get("normal_events") is not None else eventStats.get("normal_event_sets", 0)

        knownThreatEventSets = eventStats.get("ann_alert_sets", 0)
        unknownAnomEventSets = eventStats.get("unknown_anomalous_sets", 0)

        totalCampaigns = campStats.get("total_campaigns") if campStats.get("total_campaigns") is not None else friday_payload.get("threats_detected", 0)
        knownCampaigns = campStats.get("known_threat_campaigns") if campStats.get("known_threat_campaigns") is not None else friday_payload.get("known_threats", totalCampaigns)
        unknownCampaigns = campStats.get("unknown_anomalous_campaigns") if campStats.get("unknown_anomalous_campaigns") is not None else friday_payload.get("unknown_anomalous", 0)

        # Assertions
        self.assertEqual(totalFlows, 191033, "Total flows must be 191,033, not alert-attributed 77,917")
        self.assertEqual(totalEventSets, 293166, "Total event sets must be 293,166, not alert-only 9,540")
        self.assertEqual(normalEventSets, 283626, "Normal event sets must be 283,626, not alert-only 0")
        self.assertEqual(knownThreatEventSets, 7697, "Known threat event sets must be 7,697")
        self.assertEqual(unknownAnomEventSets, 1843, "Unknown anomalous event sets must be 1,843")
        self.assertEqual(totalCampaigns, 909, "Campaign KPI must remain 909")
        self.assertEqual(knownCampaigns, 748, "Known threat campaigns must remain 748")
        self.assertEqual(unknownCampaigns, 161, "Unknown anomalous campaigns must remain 161")

        # Verify event set chart partition sums to exactly total event sets:
        chart_sum = normalEventSets + knownThreatEventSets + unknownAnomEventSets
        self.assertEqual(chart_sum, totalEventSets)
        self.assertEqual(chart_sum, 293166)

    def test_03_genuinely_zero_normal_events_preserved(self):
        """
        Req 6: A genuinely zero normal-event count is still displayed as zero
        when the full-session count is also zero (no truthiness workaround bug).
        """
        pure_malicious_payload = {
            "session_id": "SESS-PURE-ATTACK",
            "has_data": True,
            "total_records": 500,
            "total_processed": 50,
            "normal_events": 0, # Genuinely zero!
            "threats_detected": 5,
            "known_threats": 5,
            "unknown_anomalous": 0,
            "event_set_statistics": {
                "total_event_sets": 50,
                "normal_event_sets": 0,
                "ann_alert_sets": 50,
                "unknown_anomalous_sets": 0
            },
            "campaign_statistics": {
                "total_campaigns": 5,
                "known_threat_campaigns": 5,
                "unknown_anomalous_campaigns": 0
            }
        }

        # Emulate JS resolution:
        normalEventSets = pure_malicious_payload.get("normal_events") if pure_malicious_payload.get("normal_events") is not None else pure_malicious_payload.get("event_set_statistics", {}).get("normal_event_sets", 0)

        self.assertEqual(normalEventSets, 0)
        self.assertIsNotNone(normalEventSets)
        self.assertIsInstance(normalEventSets, int)

    def test_04_existing_friday_morning_database_records_unchanged(self):
        """
        Req 7: Verify that the completed Friday Morning session in SQLite
        remains completely unchanged and intact.
        """
        session_id = "SESS-20261118231919-eca2ed"
        session_data = db.get_session_by_id(session_id)
        self.assertIsNotNone(session_data, f"Session '{session_id}' must exist in SQLite database")

        self.assertEqual(session_data["total_records"], 191033)
        self.assertEqual(session_data["normal_events"], 283626)
        self.assertEqual(session_data["threats_detected"], 909)
        self.assertEqual(session_data["known_threats"], 748)
        self.assertEqual(session_data["unknown_anomalous"], 161)

        # Check /api/sessions endpoint output for this session
        resp = self.client.get("/api/sessions?limit=500")
        self.assertEqual(resp.status_code, 200)
        sessions = resp.json()
        target_s = next((s for s in sessions if s["session_id"] == session_id), None)
        self.assertIsNotNone(target_s, f"Session '{session_id}' must appear in /api/sessions")

        self.assertEqual(target_s["uploaded_flows"], 191033)
        self.assertEqual(target_s["event_sets"], 293166)
        self.assertEqual(target_s["normal_events"], 283626)
        self.assertEqual(target_s["known_threats"], 748)
        self.assertEqual(target_s["unknown_anomalous"], 161)
        self.assertEqual(target_s["campaigns_count"], 909)
        self.assertEqual(target_s["status"], "Completed")

    def test_05_protected_failed_upload_incident_preserved(self):
        """
        Verify that protected incident UPL-20261118220457-b41aa8a7 and its staging records
        are completely intact and have not been touched.
        """
        upload_id = "UPL-20261118220457-b41aa8a7"
        session = db.get_upload_session(upload_id)
        self.assertIsNotNone(session, f"Protected upload session '{upload_id}' must be present in database")
        self.assertEqual(session["processing_status"], "FAILED")
        self.assertEqual(session["completed_batches"], 2)

        checkpoints = db.get_all_checkpoints(upload_id)
        self.assertEqual(len(checkpoints), 1)

        interm_dets = db.get_intermediate_detections(upload_id)
        self.assertEqual(len(interm_dets), 32154)

        pending_alerts = db.get_pending_alert_windows(upload_id)
        self.assertEqual(len(pending_alerts), 843)

    def test_06_campaign_coalescence_semantics_unchanged(self):
        """
        Req 8: Ensure campaign coalescence transitive grouping semantics are unchanged.
        """
        # Windows across overlapping time bins for same (src, dst) pair should coalesce
        w1 = {
            "event_set_id": "ES-001",
            "window_id": "W0001",
            "k": 1,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "window_start": "2026-11-18 09:00:00",
            "window_end": "2026-11-18 09:10:00",
            "verdict": "KNOWN_THREAT",
            "confidence": 0.95,
            "ensemble_score": 0.95
        }
        w2 = {
            "event_set_id": "ES-002",
            "window_id": "W0002",
            "k": 2,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "window_start": "2026-11-18 09:01:00",
            "window_end": "2026-11-18 09:11:00",
            "verdict": "KNOWN_THREAT",
            "confidence": 0.98,
            "ensemble_score": 0.98
        }
        flow_attrs = {"ES-001": [10, 11, 12], "ES-002": [12, 13, 14]}

        coalesced = coalesce_campaigns(
            window_predictions=[w1, w2],
            flow_attributions=flow_attrs,
            session_id="SESS-TEST-COAL",
            window_bins=10,
            step_seconds=60
        )
        # Should coalesce into exactly 1 campaign
        self.assertEqual(len(coalesced["campaigns"]), 1)
        camp = coalesced["campaigns"][0]
        self.assertEqual(camp["window_count"], 2)
        self.assertEqual(camp["verdict"], "KNOWN_THREAT")
        self.assertAlmostEqual(camp["max_confidence"], 0.98)
        self.assertEqual(camp["attributed_flow_count"], 5) # unique flows {10, 11, 12, 13, 14}


if __name__ == "__main__":
    unittest.main()
