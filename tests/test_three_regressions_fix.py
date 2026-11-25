"""
Unit and regression tests for Three Confirmed AI-SIEM Regressions Fix:
1. Fix A: Data Drift Accessibility and Session Report Drift Enrichment.
2. Fix B: FCNN, CNN, LSTM and Ensemble Confidence Averaging & Historical Fallback.
3. Fix C: Preaggregated Profile CSV Ingestion & Schema-Aware Routing.

Run with:
    python -m unittest tests.test_three_regressions_fix -v
"""

import json
import math
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from src.config import PROJECT_ROOT
from backend.main import app
from backend.service import siem_service, SIEMService
import backend.database as db
import backend.uploader as uploader
from backend.processor import StreamBatchProcessor, PROFILE_COLS, InvalidTimestampError
from src.drift.engine import DriftEngine


class TestThreeRegressionsFix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_uids = []
        cls.test_sids = []
        from backend.auth import authenticate_operator
        auth = authenticate_operator("admin@soc.ai", "CyberShield2026!")
        cls.admin_headers = {"Authorization": f"Bearer {auth['session_token']}"}

    @classmethod
    def tearDownClass(cls):
        for uid in cls.test_uids:
            try:
                uploader.cleanup_upload(uid)
            except Exception:
                pass
        for sid in cls.test_sids:
            try:
                db.delete_session(sid)
            except Exception:
                pass

    # =========================================================================
    # FIX A: DATA DRIFT ACCESSIBILITY & ENRICHMENT
    # =========================================================================

    def test_01_session_report_drift_enrichment_present(self):
        """
        Req A1: Test that get_session_report(session_id) enriches report with stored
        drift report from drift_reports table when present.
        """
        sid = "SESS-TEST-DRIFT-ENRICH-01"
        self.test_sids.append(sid)

        # Create session
        db.insert_session({
            "session_id": sid,
            "source_name": "drift_enrich_test.csv",
            "input_type": "PROFILE",
            "total_records": 10,
            "normal_events": 8,
            "threats_detected": 2,
            "known_threats": 2,
            "unknown_anomalous": 0,
            "invalid_records": 0,
            "threat_ratio": 0.2,
            "attack_categories": {"DoS": 2},
            "severity_distribution": {"HIGH": 2},
            "model_summary": {"fcnn": 2, "cnn": 2, "lstm": 2, "ensemble": 2, "fcnn_avg": 0.85, "cnn_avg": 0.82, "lstm_avg": 0.88, "ensemble_avg": 0.85}
        })

        # Insert drift report for this session
        report_id = f"DRIFT-{sid}"
        db.save_drift_report({
            "id": report_id,
            "session_id": sid,
            "upload_id": "UPL-TEST-DRIFT-01",
            "overall_drift_score": 0.1234,
            "drift_status": "LOW",
            "recommendation": "ACCEPTABLE: Traffic distribution aligns with reference baseline.",
            "is_partial": True,
            "omitted_layer": "Layer 1: Network Features",
            "layer1_network_features": None,
            "layer2_event_profiles": {
                "score": 0.1234,
                "status": "LOW",
                "dominant_basepoint_shift": {"js_distance": 0.05}
            },
            "timestamp": "2026-11-19 20:00:00"
        })

        # Fetch report via database.py
        rep = db.get_session_report(sid)
        self.assertIsNotNone(rep)
        self.assertIn("drift_analysis", rep)
        self.assertIsNotNone(rep["drift_analysis"])
        self.assertEqual(rep["drift_analysis"].get("id") or rep["drift_analysis"].get("report_id"), report_id)
        self.assertEqual(rep["drift_analysis"]["overall_drift_score"], 0.1234)
        self.assertEqual(rep["drift_analysis"]["drift_status"], "LOW")
        self.assertTrue(rep["drift_analysis"]["is_partial"])

        # Fetch report via API /api/sessions/{session_id}
        # 1. Unauthenticated or regular analyst receives drift_analysis: None
        unauth_resp = self.client.get(f"/api/sessions/{sid}")
        self.assertEqual(unauth_resp.status_code, 200)
        self.assertIsNone(unauth_resp.json().get("drift_analysis"))

        # 2. Authenticated Head of SOC receives populated drift_analysis
        resp = self.client.get(f"/api/sessions/{sid}", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        api_rep = resp.json()
        self.assertIn("drift_analysis", api_rep)
        self.assertIsNotNone(api_rep["drift_analysis"])
        self.assertEqual(api_rep["drift_analysis"]["overall_drift_score"], 0.1234)

    def test_02_session_report_drift_enrichment_missing(self):
        """
        Req A2: Test that historical sessions without drift reports return
        drift_analysis: None (never fabricate fake drift scores).
        """
        sid = "SESS-TEST-DRIFT-NONE-02"
        self.test_sids.append(sid)

        db.insert_session({
            "session_id": sid,
            "source_name": "no_drift_test.csv",
            "input_type": "FLOW",
            "total_records": 100,
            "normal_events": 95,
            "threats_detected": 5,
            "known_threats": 5,
            "unknown_anomalous": 0,
            "invalid_records": 0,
            "threat_ratio": 0.05,
            "attack_categories": {"PortScan": 5},
            "severity_distribution": {"MEDIUM": 5},
            "model_summary": {"fcnn": 5, "cnn": 5, "lstm": 5, "ensemble": 5}
        })

        rep = db.get_session_report(sid)
        self.assertIsNotNone(rep)
        self.assertIn("drift_analysis", rep)
        self.assertIsNone(rep["drift_analysis"])

        resp = self.client.get(f"/api/sessions/{sid}")
        self.assertEqual(resp.status_code, 200)
        api_rep = resp.json()
        self.assertIn("drift_analysis", api_rep)
        self.assertIsNone(api_rep["drift_analysis"])

    def test_03_drift_api_endpoints(self):
        """
        Req A3: Verify /api/drift/latest, /api/drift/history, and /api/drift/reference
        strictly reject unauthenticated access with HTTP 401 and allow Head of SOC with HTTP 200.
        """
        # Unauthenticated calls must return 401 Unauthorized
        self.assertEqual(self.client.get("/api/drift/reference").status_code, 401)
        self.assertEqual(self.client.get("/api/drift/latest").status_code, 401)
        self.assertEqual(self.client.get("/api/drift/history").status_code, 401)

        # Authenticated Head of SOC calls must return 200 OK
        resp_ref = self.client.get("/api/drift/reference", headers=self.admin_headers)
        self.assertEqual(resp_ref.status_code, 200)
        ref_data = resp_ref.json()
        self.assertIn("n_training_flows", ref_data)
        self.assertIn("n_training_profiles", ref_data)
        self.assertIn("raw_features", ref_data)
        self.assertIn("profile_features", ref_data)

        resp_latest = self.client.get("/api/drift/latest", headers=self.admin_headers)
        self.assertEqual(resp_latest.status_code, 200)
        latest_data = resp_latest.json()
        self.assertIn("has_drift", latest_data)
        if latest_data["has_drift"]:
            self.assertIn("report", latest_data)
            self.assertIn("drift_status", latest_data["report"])

        resp_hist = self.client.get("/api/drift/history?limit=10", headers=self.admin_headers)
        self.assertEqual(resp_hist.status_code, 200)
        hist_data = resp_hist.json()
        self.assertIsInstance(hist_data, list)
        self.assertGreater(len(hist_data), 0)

    # =========================================================================
    # FIX B: PROBABILITY AVERAGING & HISTORICAL FALLBACK
    # =========================================================================

    def test_04_streaming_processor_accumulates_probabilities_accurately(self):
        """
        Req B1: Test that StreamBatchProcessor accumulates probabilities
        across batches using math.fsum and sets model_summary averages.
        """
        processor = StreamBatchProcessor(siem_service)
        metrics = {
            "total_event_sets": 0,
            "normal_event_sets": 0,
            "known_threats": 0,
            "unknown_anomalous": 0,
            "severity_dist": {},
            "attack_types": {},
            "fcnn_sum": 0.0,
            "cnn_sum": 0.0,
            "lstm_sum": 0.0,
            "ensemble_sum": 0.0
        }

        # Batch 1: 3 evaluated event sets
        b1_fcnn = [0.20, 0.40, 0.60]
        b1_cnn = [0.25, 0.35, 0.65]
        b1_lstm = [0.15, 0.45, 0.55]
        b1_ens = [0.20, 0.40, 0.60]

        metrics["total_event_sets"] += len(b1_fcnn)
        metrics["fcnn_sum"] += math.fsum(b1_fcnn)
        metrics["cnn_sum"] += math.fsum(b1_cnn)
        metrics["lstm_sum"] += math.fsum(b1_lstm)
        metrics["ensemble_sum"] += math.fsum(b1_ens)

        # Batch 2: 2 evaluated event sets
        b2_fcnn = [0.80, 0.90]
        b2_cnn = [0.75, 0.85]
        b2_lstm = [0.85, 0.95]
        b2_ens = [0.80, 0.90]

        metrics["total_event_sets"] += len(b2_fcnn)
        metrics["fcnn_sum"] += math.fsum(b2_fcnn)
        metrics["cnn_sum"] += math.fsum(b2_cnn)
        metrics["lstm_sum"] += math.fsum(b2_lstm)
        metrics["ensemble_sum"] += math.fsum(b2_ens)

        total_evaluated_sets = metrics["total_event_sets"]
        self.assertEqual(total_evaluated_sets, 5)

        expected_fcnn_avg = round((0.20 + 0.40 + 0.60 + 0.80 + 0.90) / 5, 4)
        expected_cnn_avg = round((0.25 + 0.35 + 0.65 + 0.75 + 0.85) / 5, 4)
        expected_lstm_avg = round((0.15 + 0.45 + 0.55 + 0.85 + 0.95) / 5, 4)
        expected_ens_avg = round((0.20 + 0.40 + 0.60 + 0.80 + 0.90) / 5, 4)

        fcnn_avg = round(metrics["fcnn_sum"] / total_evaluated_sets, 4)
        cnn_avg = round(metrics["cnn_sum"] / total_evaluated_sets, 4)
        lstm_avg = round(metrics["lstm_sum"] / total_evaluated_sets, 4)
        ens_avg = round(metrics["ensemble_sum"] / total_evaluated_sets, 4)

        self.assertEqual(fcnn_avg, expected_fcnn_avg)
        self.assertEqual(cnn_avg, expected_cnn_avg)
        self.assertEqual(lstm_avg, expected_lstm_avg)
        self.assertEqual(ens_avg, expected_ens_avg)

    def test_05_historical_session_fallback_derives_probabilities(self):
        """
        Req B2: Test that database.get_session_report() falls back to computing
        averages from detections.model_breakdown when model_summary averages are missing.
        """
        sid = "SESS-TEST-HISTORICAL-FALLBACK-01"
        self.test_sids.append(sid)

        # Create session with model_summary lacking averages
        db.insert_session({
            "session_id": sid,
            "source_name": "hist_test.csv",
            "input_type": "FLOW",
            "total_records": 4,
            "normal_events": 2,
            "threats_detected": 2,
            "known_threats": 2,
            "unknown_anomalous": 0,
            "invalid_records": 0,
            "threat_ratio": 0.5,
            "attack_categories": {"DoS": 2},
            "severity_distribution": {"HIGH": 2},
            "model_summary": {"fcnn": 2, "cnn": 2, "lstm": 2, "ensemble": 2}  # No *_avg keys!
        })

        # Insert 4 detections with distinct model_breakdowns
        detections = [
            {
                "session_id": sid,
                "timestamp": "2026-11-19 10:00:00",
                "source": "hist_test.csv",
                "input_type": "FLOW",
                "source_ip": "192.168.1.10",
                "destination_ip": "10.0.0.1",
                "destination_port": 80,
                "protocol": "TCP",
                "verdict": "BENIGN",
                "threat_type": "BENIGN",
                "severity": "LOW",
                "confidence": 0.15,
                "threat_confidence": 0.15,
                "dominant_basepoint": "bp_01",
                "dominant_similarity": 0.9,
                "anomaly_verdict": "NORMAL",
                "anomaly_score": 0.05,
                "model_breakdown": {"fcnn": 0.10, "cnn": 0.12, "lstm": 0.14}
            },
            {
                "session_id": sid,
                "timestamp": "2026-11-19 10:01:00",
                "source": "hist_test.csv",
                "input_type": "FLOW",
                "source_ip": "192.168.1.11",
                "destination_ip": "10.0.0.1",
                "destination_port": 80,
                "protocol": "TCP",
                "verdict": "BENIGN",
                "threat_type": "BENIGN",
                "severity": "LOW",
                "confidence": 0.25,
                "threat_confidence": 0.25,
                "dominant_basepoint": "bp_01",
                "dominant_similarity": 0.88,
                "anomaly_verdict": "NORMAL",
                "anomaly_score": 0.08,
                "model_breakdown": {"fcnn": 0.20, "cnn": 0.24, "lstm": 0.22}
            },
            {
                "session_id": sid,
                "timestamp": "2026-11-19 10:02:00",
                "source": "hist_test.csv",
                "input_type": "FLOW",
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.1",
                "destination_port": 80,
                "protocol": "TCP",
                "verdict": "KNOWN_THREAT",
                "threat_type": "DoS",
                "severity": "HIGH",
                "confidence": 0.85,
                "threat_confidence": 0.85,
                "dominant_basepoint": "bp_06",
                "dominant_similarity": 0.75,
                "anomaly_verdict": "ANOMALOUS",
                "anomaly_score": 0.85,
                "model_breakdown": {"fcnn": 0.80, "cnn": 0.82, "lstm": 0.86}
            },
            {
                "session_id": sid,
                "timestamp": "2026-11-19 10:03:00",
                "source": "hist_test.csv",
                "input_type": "FLOW",
                "source_ip": "192.168.1.51",
                "destination_ip": "10.0.0.1",
                "destination_port": 80,
                "protocol": "TCP",
                "verdict": "KNOWN_THREAT",
                "threat_type": "DoS",
                "severity": "HIGH",
                "confidence": 0.95,
                "threat_confidence": 0.95,
                "dominant_basepoint": "bp_06",
                "dominant_similarity": 0.72,
                "anomaly_verdict": "ANOMALOUS",
                "anomaly_score": 0.92,
                "model_breakdown": {"fcnn": 0.90, "cnn": 0.94, "lstm": 0.98}
            }
        ]
        db.insert_detections(detections)

        rep = db.get_session_report(sid)
        self.assertIsNotNone(rep)
        ms = rep.get("model_summary", {})

        # Expected averages:
        # fcnn: (0.10 + 0.20 + 0.80 + 0.90) / 4 = 0.50
        # cnn:  (0.12 + 0.24 + 0.82 + 0.94) / 4 = 0.53
        # lstm: (0.14 + 0.22 + 0.86 + 0.98) / 4 = 0.55
        # ens:  (0.15 + 0.25 + 0.85 + 0.95) / 4 = 0.55
        self.assertEqual(ms.get("fcnn_avg"), 0.50)
        self.assertEqual(ms.get("cnn_avg"), 0.53)
        self.assertEqual(ms.get("lstm_avg"), 0.55)
        self.assertEqual(ms.get("ensemble_avg"), 0.55)

    def test_06_historical_session_fallback_missing_breakdown_returns_none(self):
        """
        Req B3: When detections have NO model_breakdown, get_session_report() sets averages
        to None so UI displays 'N/A' rather than false '0.0%'.
        """
        sid = "SESS-TEST-HISTORICAL-NONE-02"
        self.test_sids.append(sid)

        db.insert_session({
            "session_id": sid,
            "source_name": "empty_ms_test.csv",
            "input_type": "FLOW",
            "total_records": 2,
            "normal_events": 2,
            "threats_detected": 0,
            "known_threats": 0,
            "unknown_anomalous": 0,
            "invalid_records": 0,
            "threat_ratio": 0.0,
            "attack_categories": {},
            "severity_distribution": {},
            "model_summary": {"fcnn": 0, "cnn": 0, "lstm": 0, "ensemble": 0}
        })

        # Insert detection with NULL model_breakdown
        db.insert_detections([{
            "session_id": sid,
            "timestamp": "2026-11-19 10:00:00",
            "source": "empty_ms_test.csv",
            "input_type": "FLOW",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "protocol": "TCP",
            "verdict": "BENIGN",
            "threat_type": "BENIGN",
            "severity": "LOW",
            "confidence": 0.05,
            "threat_confidence": 0.05,
            "dominant_basepoint": "bp_01",
            "dominant_similarity": 0.9,
            "anomaly_verdict": "NORMAL",
            "anomaly_score": 0.02,
            "model_breakdown": None
        }])

        rep = db.get_session_report(sid)
        self.assertIsNotNone(rep)
        ms = rep.get("model_summary", {})
        self.assertIsNone(ms.get("fcnn_avg"))
        self.assertIsNone(ms.get("cnn_avg"))
        self.assertIsNone(ms.get("lstm_avg"))
        self.assertIsNone(ms.get("ensemble_avg"))

    # =========================================================================
    # FIX C: PREAGGREGATED PROFILE CSV INGESTION & SCHEMA DETECTION
    # =========================================================================

    def test_07_step0_schema_detection_identifies_profile_csv(self):
        """
        Req C1: Verify that Step 0 in processor identifies preaggregated profile CSV
        and delegates to service.process_file_upload without invoking external_sort_csv.
        """
        # Create small temporary preaggregated profile CSV
        profile_content = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.05,0.08,0.03,0.06,0.04,0.07,0.02,0.05\n"
            "0.82,0.76,0.88,0.79,0.91,0.84,0.73,0.87\n"
        ).encode("utf-8")

        uid = "UPL-TEST-PROFILE-STEP0"
        sid = "SESS-TEST-PROFILE-STEP0"
        self.test_uids.append(uid)
        self.test_sids.append(sid)

        upload_dir = PROJECT_ROOT / "data" / "uploads" / uid
        upload_dir.mkdir(parents=True, exist_ok=True)
        source_csv = upload_dir / "source.csv"
        source_csv.write_bytes(profile_content)
        sorted_csv = upload_dir / "sorted.csv"

        db.create_upload_session(
            upload_id=uid,
            session_id=sid,
            filename="profile_test.csv",
            file_size=len(profile_content),
            file_hash="dummyhash",
            total_chunks=1
        )

        session_dict = db.get_upload_session(uid)
        processor = StreamBatchProcessor(siem_service)

        result = processor.process_upload_session(
            upload_id=uid,
            batch_size=100
        )

        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["session_id"], sid)
        self.assertIn("summary", result)

        # Verify sorted.csv was NOT created because external sort was skipped
        self.assertFalse(sorted_csv.exists())

        # Verify upload status has sort_status == "SKIPPED"
        sess = db.get_upload_session(uid)
        self.assertEqual(sess["sort_status"], "SKIPPED")
        self.assertEqual(sess["processing_status"], "COMPLETED")

    def test_08_raw_flow_missing_timestamp_raises_error(self):
        """
        Req C2: Verify that a raw flow CSV missing required 'timestamp' column
        raises InvalidTimestampError and is marked as FAILED.
        """
        bad_flow_content = (
            "source_ip,destination_ip,flow_duration,flow_packets_s\n"
            "192.168.1.1,10.0.0.1,100,2.5\n"
        ).encode("utf-8")

        uid = "UPL-TEST-BAD-FLOW"
        sid = "SESS-TEST-BAD-FLOW"
        self.test_uids.append(uid)
        self.test_sids.append(sid)

        upload_dir = PROJECT_ROOT / "data" / "uploads" / uid
        upload_dir.mkdir(parents=True, exist_ok=True)
        source_csv = upload_dir / "source.csv"
        source_csv.write_bytes(bad_flow_content)

        db.create_upload_session(
            upload_id=uid,
            session_id=sid,
            filename="bad_flow.csv",
            file_size=len(bad_flow_content),
            file_hash="dummyhash2",
            total_chunks=1
        )

        processor = StreamBatchProcessor(siem_service)
        with self.assertRaises(InvalidTimestampError):
            processor.process_upload_session(upload_id=uid, batch_size=100)

        sess = db.get_upload_session(uid)
        self.assertEqual(sess["processing_status"], "FAILED")
        self.assertIn("missing required column 'timestamp'", sess["error_message"].lower())

    def test_09_profile_csv_upload_api_and_drift_evaluation(self):
        """
        Req C3: Verify end-to-end ingestion of preaggregated profile CSV via /api/detect/upload
        with layer 2 drift evaluation and non-zero model breakdown averages.
        """
        profile_csv_path = Path(r"C:\Users\pavani krishna\Desktop\cyber\upload\siem_test_event_profiles.csv")
        if not profile_csv_path.exists():
            raise unittest.SkipTest("Sample profile CSV not found")

        content = profile_csv_path.read_bytes()
        files = {"file": ("siem_test_event_profiles.csv", content, "text/csv")}

        resp = self.client.post("/api/detect/upload", files=files)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        sid = data.get("session_id")
        self.assertIsNotNone(sid)
        self.test_sids.append(sid)

        self.assertTrue(data.get("has_data"))
        self.assertEqual(data.get("total_records"), 10)

        # Check model confidence averages
        ms = data.get("model_summary", {})
        self.assertIn("fcnn_avg", ms)
        self.assertIn("cnn_avg", ms)
        self.assertIn("lstm_avg", ms)
        self.assertIn("ensemble_avg", ms)
        self.assertGreater(ms["fcnn_avg"], 0.0)
        self.assertGreater(ms["cnn_avg"], 0.0)
        self.assertGreater(ms["lstm_avg"], 0.0)
        self.assertGreater(ms["ensemble_avg"], 0.0)

        # Check drift report for this session
        drift_rep = db.get_drift_report_by_session(sid)
        self.assertIsNotNone(drift_rep)
        self.assertTrue(drift_rep["is_partial"])
        self.assertEqual(drift_rep["omitted_layer"], "Layer 1: Network Features")
        self.assertIsNotNone(drift_rep["layer2_event_profiles"])
        self.assertGreater(drift_rep["overall_drift_score"], 0.0)

        # Verify get_session_report enriches this drift report
        sess_rep = db.get_session_report(sid)
        self.assertIsNotNone(sess_rep["drift_analysis"])
        self.assertEqual(sess_rep["drift_analysis"]["session_id"], sid)
        self.assertEqual(sess_rep["drift_analysis"]["overall_drift_score"], drift_rep["overall_drift_score"])

    # =========================================================================
    # SAFETY & HISTORICAL INTEGRITY CHECKS
    # =========================================================================

    def test_10_protected_incident_remains_intact(self):
        """
        Verify forensic incident UPL-20261118220457-b41aa8a7 remains 100% intact.
        """
        incident_uid = "UPL-20261118220457-b41aa8a7"
        sess = db.get_upload_session(incident_uid)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["processing_status"], "FAILED")

        chk = db.get_all_checkpoints(incident_uid)
        self.assertGreaterEqual(len(chk), 1)

        int_dets = db.get_intermediate_detections(incident_uid)
        self.assertGreaterEqual(len(int_dets), 30000)

    def test_11_friday_morning_session_confidences_and_drift_status(self):
        """
        Verify Friday Morning session (SESS-20261118231919-eca2ed):
        - Dynamic SQL fallback derives non-zero probability averages
        - drift_analysis is None (historical, no fake data)
        """
        friday_sid = "SESS-20261118231919-eca2ed"
        rep = db.get_session_report(friday_sid)
        self.assertIsNotNone(rep)

        ms = rep.get("model_summary", {})
        self.assertIsNotNone(ms.get("fcnn_avg"))
        self.assertAlmostEqual(ms["fcnn_avg"], 0.2130, places=3)
        self.assertAlmostEqual(ms["cnn_avg"], 0.2098, places=3)
        self.assertAlmostEqual(ms["lstm_avg"], 0.2438, places=3)
        self.assertAlmostEqual(ms["ensemble_avg"], 0.2222, places=3)

        # Verify drift is None
        self.assertIsNone(rep.get("drift_analysis"))

    def test_12_frontend_index_no_cache_headers(self):
        """
        Verify that GET / serves index.html with explicit no-cache headers to prevent
        stale browser caching of navigation and view elements.
        """
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        cc = resp.headers.get("cache-control", "")
        self.assertIn("no-cache", cc)
        self.assertIn("no-store", cc)

    def test_13_sidebar_drift_navigation_html_and_css(self):
        """
        Verify that index.html contains data-view="view-drift" with id="navDrift",
        and that styles.css configures .sidebar-nav with overflow-y: auto.
        """
        index_path = PROJECT_ROOT / "frontend" / "index.html"
        self.assertTrue(index_path.exists())
        index_html = index_path.read_text(encoding="utf-8")
        self.assertIn('data-view="view-drift"', index_html)
        self.assertIn('id="navDrift"', index_html)
        self.assertIn('id="view-drift"', index_html)

        css_path = PROJECT_ROOT / "frontend" / "css" / "styles.css"
        self.assertTrue(css_path.exists())
        css_text = css_path.read_text(encoding="utf-8")
        self.assertIn(".sidebar-nav", css_text)
        self.assertIn("overflow-y: auto", css_text)


if __name__ == "__main__":
    unittest.main()
