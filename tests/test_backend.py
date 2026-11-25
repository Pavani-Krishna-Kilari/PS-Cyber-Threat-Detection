"""
Unit tests for FastAPI backend endpoints and file parsing.
Run with:
    python -m unittest tests.test_backend -v
"""

import io
import unittest
from pathlib import Path
import numpy as np
from fastapi.testclient import TestClient

import backend.database
from backend.main import app
from backend.parser import parse_csv_bytes, parse_txt_bytes, parse_uploaded_file
from backend.service import siem_service


class TestBackendEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db_path = backend.database.DB_PATH
        cls._orig_exp_id = siem_service.experiment_id
        cls._test_db_path = Path("data/test_detection_history_backend.db")
        backend.database.DB_PATH = cls._test_db_path
        backend.database.init_db()
        siem_service.set_experiment("A")
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        siem_service.set_experiment(cls._orig_exp_id)
        backend.database.DB_PATH = cls._orig_db_path
        if cls._test_db_path.exists():
            try:
                cls._test_db_path.unlink()
            except Exception:
                pass

    def test_status_endpoint(self):
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("models_loaded", data)

    def test_dataset_overview_endpoint(self):
        resp = self.client.get("/api/dataset/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("rows_final", data)
        self.assertIn("labels_distribution", data)

    def test_profiles_overview_endpoint(self):
        resp = self.client.get("/api/profiles/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("basepoints", data)
        self.assertIn("thresholds", data)

    def test_models_benchmarks_endpoint(self):
        resp = self.client.get("/api/models/benchmarks")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("evaluation_report", data)

    def test_predict_profile_single_verdict(self):
        payload = {
            "bp_01": 0.85,
            "bp_02": 0.20,
            "bp_03": 0.10,
            "bp_04": 0.05,
            "bp_05": 0.70,
            "bp_06": 0.80,
            "bp_07": 0.75,
            "bp_08": 0.05
        }
        resp = self.client.post("/api/models/predict/profile", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(data["verdict"], ["KNOWN_THREAT", "UNKNOWN_ANOMALOUS", "NORMAL"])
        self.assertIn("threat_confidence", data)
        self.assertIn("dominant_basepoint", data)
        self.assertIn("prediction_status", data)
        self.assertIn("predicted_class", data)
        self.assertIn("requires_investigation", data)

    def test_predict_flow_endpoint(self):
        payload = {
            "source_ip": "172.16.0.1",
            "destination_ip": "192.168.10.50",
            "source_port": 50123,
            "destination_port": 21,
            "protocol": 6,
            "flow_duration": 3000.0,
            "flow_packets_s": 700000.0,
            "flow_bytes_s": 2500000.0,
            "syn_flag_count": 2,
            "flow_count": 20
        }
        resp = self.client.post("/api/models/predict/flow", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(data["verdict"], ["KNOWN_THREAT", "UNKNOWN_ANOMALOUS", "NORMAL"])
        self.assertIn("prediction_status", data)
        self.assertIn("flow_metadata", data)

    def test_stream_event_endpoint(self):
        resp = self.client.get("/api/detect/stream")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("verdict", data)
        self.assertIn("source_ip", data)

    def test_configure_ensemble_endpoint(self):
        payload = {
            "weights": [0.4, 0.3, 0.3],
            "threshold": 0.60
        }
        resp = self.client.post("/api/ensemble/configure", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "SUCCESS")

        # Restore calibrated default ensemble configuration
        restore_payload = {
            "weights": [1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0],
            "threshold": 0.8398
        }
        self.client.post("/api/ensemble/configure", json=restore_payload)

    def test_anomaly_overview_endpoint(self):
        resp = self.client.get("/api/anomaly/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("is_ready"))
        self.assertIn("Isolation Forest", data.get("model_name"))
        self.assertIn("metrics_on_test", data)

    def test_predict_anomaly_endpoint(self):
        payload = {
            "bp_01": 0.3670, "bp_02": 0.3838, "bp_03": 0.7954, "bp_04": 0.3319,
            "bp_05": 0.3606, "bp_06": 0.5307, "bp_07": 0.4432, "bp_08": 0.4407
        }
        resp = self.client.post("/api/models/predict/anomaly", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("is_anomaly", data)
        self.assertEqual(data["verdict"], "NORMAL")

    def test_assistant_chat_endpoint(self):
        payload = {"query": "Explain FTP-Patator detection pattern"}
        resp = self.client.post("/api/assistant/chat", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("reply", data)
        self.assertIn("category", data)
        self.assertIn("suggestions", data)

    def test_incident_contain_endpoint_removed_returns_404(self):
        """Verifies that the removed incident containment endpoint is no longer accessible."""
        payload = {
            "attacker_ip": "172.16.0.1",
            "victim_ip": "192.168.10.50",
            "target_port": 21,
            "attack_type": "FTP-Patator Brute Force",
            "platform": "iptables"
        }
        resp = self.client.post("/api/incident/contain", json=payload)
        self.assertEqual(resp.status_code, 404)

    def test_predict_profile_known_threat(self):
        payload = {
            "bp_01": 0.5630, "bp_02": 0.3430, "bp_03": 0.9424, "bp_04": 0.2136,
            "bp_05": 0.2260, "bp_06": 0.7550, "bp_07": 0.5797, "bp_08": 0.5215
        }
        resp = self.client.post("/api/models/predict/profile", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "KNOWN_THREAT")
        self.assertEqual(data["prediction_status"], "KNOWN_THREAT")
        self.assertTrue(data["requires_investigation"])
        self.assertGreaterEqual(data["confidence"], 0.8398)

    def test_predict_profile_unknown_anomalous(self):
        payload = {
            "bp_01": 0.85, "bp_02": 0.20, "bp_03": 0.10, "bp_04": 0.05,
            "bp_05": 0.70, "bp_06": 0.80, "bp_07": 0.75, "bp_08": 0.05
        }
        resp = self.client.post("/api/models/predict/profile", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "UNKNOWN_ANOMALOUS")
        self.assertEqual(data["prediction_status"], "UNKNOWN_ANOMALOUS")
        self.assertTrue(data["requires_investigation"])

    def test_predict_profile_normal(self):
        payload = {
            "bp_01": 0.0925, "bp_02": 0.9765, "bp_03": 0.3905, "bp_04": 0.6040,
            "bp_05": 0.5797, "bp_06": 0.5831, "bp_07": 0.6330, "bp_08": 0.6870
        }
        resp = self.client.post("/api/models/predict/profile", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "NORMAL")
        self.assertEqual(data["prediction_status"], "NORMAL")
        self.assertFalse(data["requires_investigation"])
        self.assertGreaterEqual(data["confidence"], 0.70)

    def test_history_filtering_by_verdict(self):
        # Insert a known flow
        payload = {
            "source_ip": "172.16.0.1", "destination_ip": "192.168.10.50",
            "source_port": 50123, "destination_port": 21, "protocol": 6,
            "flow_duration": 3000.0, "flow_packets_s": 700000.0,
            "flow_bytes_s": 2500000.0, "syn_flag_count": 2, "flow_count": 20
        }
        self.client.post("/api/models/predict/flow", json=payload)

        # Query all
        resp_all = self.client.get("/api/history?verdict=ALL")
        self.assertEqual(resp_all.status_code, 200)

        # Query threats
        resp_thr = self.client.get("/api/history?verdict=THREAT")
        self.assertEqual(resp_thr.status_code, 200)

        # Query known threats specifically
        resp_known = self.client.get("/api/history?verdict=KNOWN_THREAT")
        self.assertEqual(resp_known.status_code, 200)


class TestFileParsers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db_path = backend.database.DB_PATH
        cls._test_db_path = Path("data/test_detection_history_parsers.db")
        backend.database.DB_PATH = cls._test_db_path
        backend.database.init_db()

    @classmethod
    def tearDownClass(cls):
        backend.database.DB_PATH = cls._orig_db_path
        if cls._test_db_path.exists():
            try:
                cls._test_db_path.unlink()
            except Exception:
                pass

    def test_csv_profile_parser(self):
        csv_data = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8\n"
            "0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0\n"
        ).encode("utf-8")
        df, kind = parse_csv_bytes(csv_data)
        self.assertEqual(kind, "profile")
        self.assertEqual(len(df), 2)

    def test_csv_flow_parser(self):
        csv_data = (
            "source_ip,destination_ip,destination_port,flow_packets_s,flow_bytes_s,syn_flag_count,flow_duration\n"
            "172.16.0.1,192.168.10.50,21,550000,2000000,2,4000\n"
        ).encode("utf-8")
        df, kind = parse_csv_bytes(csv_data)
        self.assertEqual(kind, "flow")
        self.assertEqual(len(df), 1)

    def test_txt_parser_key_values(self):
        txt_data = (
            "source_ip: 172.16.0.1\n"
            "destination_ip: 192.168.10.50\n"
            "flow_packets_s: 600000\n"
            "flow_bytes_s: 2500000\n"
            "syn_flag_count: 2\n"
        ).encode("utf-8")
        df, kind = parse_txt_bytes(txt_data)
        self.assertGreaterEqual(len(df), 1)

    def test_upload_file_endpoint_csv(self):
        client = TestClient(app)
        csv_content = b"bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n0.5,0.2,0.1,0.0,0.4,0.6,0.5,0.1\n"
        files = {"file": ("test.csv", csv_content, "text/csv")}
        resp = client.post("/api/detect/upload", files=files)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_processed"], 1)
        self.assertIn("threats_detected", data)


class TestCSVIngestionRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db_path = backend.database.DB_PATH
        cls._orig_exp_id = siem_service.experiment_id
        cls._test_db_path = Path("data/test_detection_history_csv_regression.db")
        backend.database.DB_PATH = cls._test_db_path
        backend.database.init_db()
        siem_service.set_experiment("B")
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        siem_service.set_experiment(cls._orig_exp_id)
        backend.database.DB_PATH = cls._orig_db_path
        if cls._test_db_path.exists():
            try:
                cls._test_db_path.unlink()
            except Exception:
                pass

    def test_identical_duration_and_flow_duration_merged_safely(self):
        csv_bytes = (
            "protocol,dst_port,duration,fwd_pkts,bwd_pkts,flow_packets_s,flow_bytes_s,syn_flag_count,flow_duration\n"
            "6,80,5000,10,5,100,2000,2,5000\n"
            "17,443,12000,20,15,50,1500,0,12000\n"
        ).encode("utf-8")
        df, kind = parse_csv_bytes(csv_bytes)
        self.assertEqual(kind, "flow")
        self.assertIn("flow_duration", df.columns)
        self.assertEqual(list(df.columns).count("flow_duration"), 1)
        self.assertEqual(df["flow_duration"].tolist(), [5000.0, 12000.0])

    def test_conflicting_duration_and_flow_duration_rejected(self):
        csv_bytes = (
            "protocol,dst_port,duration,fwd_pkts,bwd_pkts,flow_packets_s,flow_bytes_s,syn_flag_count,flow_duration\n"
            "6,80,5000,10,5,100,2000,2,9999\n"
        ).encode("utf-8")
        with self.assertRaises(ValueError) as ctx:
            parse_csv_bytes(csv_bytes)
        self.assertIn("Conflicting values detected between columns mapping to 'flow_duration'", str(ctx.exception))

        # Also verify API endpoint returns HTTP 400
        resp = self.client.post("/api/detect/upload", files={"file": ("conflicting.csv", csv_bytes, "text/csv")})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Conflicting values detected", resp.json()["detail"])

    def test_duplicate_canonical_headers(self):
        # Identical duplicate canonical headers: safely merged
        csv_identical = (
            "flow_duration,flow_duration,flow_packets_s,flow_bytes_s,syn_flag_count\n"
            "3000,3000,500,1000,1\n"
        ).encode("utf-8")
        df, kind = parse_csv_bytes(csv_identical)
        self.assertEqual(kind, "flow")
        self.assertEqual(list(df.columns).count("flow_duration"), 1)

        # Conflicting duplicate canonical headers: rejected with ValueError / HTTP 400
        csv_conflicting = (
            "flow_duration,flow_duration,flow_packets_s,flow_bytes_s,syn_flag_count\n"
            "3000,7000,500,1000,1\n"
        ).encode("utf-8")
        with self.assertRaises(ValueError) as ctx:
            parse_csv_bytes(csv_conflicting)
        self.assertIn("Conflicting values detected", str(ctx.exception))

        resp = self.client.post("/api/detect/upload", files={"file": ("dup_conflict.csv", csv_conflicting, "text/csv")})
        self.assertEqual(resp.status_code, 400)

        # Duplicate basepoint headers: safely merged
        csv_bp_identical = (
            "bp_01,bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.5,0.5,0.2,0.1,0.0,0.4,0.6,0.5,0.1\n"
        ).encode("utf-8")
        df_bp, kind_bp = parse_csv_bytes(csv_bp_identical)
        self.assertEqual(kind_bp, "profile")
        self.assertEqual(list(df_bp.columns).count("bp_01"), 1)

    def test_ground_truth_label_exclusion(self):
        csv_bytes = (
            "flow_duration,flow_packets_s,flow_bytes_s,syn_flag_count,actual_label,threat_type,label,attack_type,target_binary\n"
            "3000,500,1000,1,THREAT,Scanning-like,ATTACK,PortScan,1\n"
        ).encode("utf-8")
        df, kind = parse_csv_bytes(csv_bytes)
        self.assertEqual(kind, "flow")
        for lbl in ["actual_label", "threat_type", "label", "attack_type", "target_binary"]:
            self.assertNotIn(lbl, df.columns)

    def test_missing_timestamp_source_ip_destination_ip_returns_422(self):
        # CSV with flow metrics but without timestamp, source_ip, destination_ip (like combined_ai_siem_dataset.csv)
        csv_bytes = (
            "protocol,dst_port,duration,fwd_pkts,bwd_pkts,flow_packets_s,flow_bytes_s,syn_flag_count,flow_duration,actual_label,threat_type\n"
            "6,990,8317,11,3,2,673,4,8317,THREAT,Scanning-like\n"
            "6,590,8424,6,1,1,332,4,8424,THREAT,Scanning-like\n"
        ).encode("utf-8")
        resp = self.client.post("/api/detect/upload", files={"file": ("combined_ai_siem_dataset.csv", csv_bytes, "text/csv")})
        self.assertEqual(resp.status_code, 422)
        data = resp.json()["detail"]
        self.assertEqual(data["error"], "MissingFeatureColumnsError")
        self.assertIn("Missing required flow columns", data["message"])
        self.assertIn("destination_ip", data["message"])
        self.assertIn("source_ip", data["message"])
        self.assertIn("timestamp", data["message"])
        self.assertNotIn("Inference error", str(resp.json()))

    def test_valid_raw_flow_csv_processed_successfully(self):
        lines = ["source_ip,destination_ip,source_port,destination_port,protocol,timestamp,flow_duration,flow_packets_s,flow_bytes_s,syn_flag_count"]
        for b in range(12):
            for f in range(2):
                ts = f"2017-07-04 09:{b:02d}:{f * 20:02d}"
                lines.append(f"172.16.0.1,192.168.10.50,1024,21,TCP,{ts},1500.0,500000.0,2000000.0,2")
        csv_bytes = "\n".join(lines).encode("utf-8")
        resp = self.client.post("/api/detect/upload", files={"file": ("valid_raw_flow.csv", csv_bytes, "text/csv")})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total_processed"], 1)
        self.assertEqual(data["detected_type"], "flow")

    def test_valid_bp01_through_bp08_csv_processed_successfully(self):
        csv_bytes = (
            "event_set_id,window_id,k,source_ip,destination_ip,destination_port,protocol,n_flows,bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "ES0000001,W00000,0,10.0.0.1,192.168.1.100,80,TCP,10,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0\n"
            "ES0000002,W00001,1,10.0.0.2,192.168.1.100,21,TCP,15,0.90,0.20,0.05,0.05,0.80,0.90,0.85,0.05\n"
        ).encode("utf-8")
        resp = self.client.post("/api/detect/upload", files={"file": ("valid_profiles.csv", csv_bytes, "text/csv")})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_records"], 2)
        self.assertEqual(data["detected_type"], "profile")
        self.assertGreaterEqual(data["threats_detected"], 1)
        self.assertGreaterEqual(data["normal_events"], 1)


class TestDashboardRequirements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db_path = backend.database.DB_PATH
        cls._orig_exp_id = siem_service.experiment_id
        cls._test_db_path = Path("data/test_detection_history_dashboard.db")
        backend.database.DB_PATH = cls._test_db_path
        backend.database.init_db()
        siem_service.set_experiment("A")

    @classmethod
    def tearDownClass(cls):
        siem_service.set_experiment(cls._orig_exp_id)
        backend.database.DB_PATH = cls._orig_db_path
        if cls._test_db_path.exists():
            try:
                cls._test_db_path.unlink()
            except Exception:
                pass

    def setUp(self):
        self.client = TestClient(app)
        self.client.delete("/api/history")

    def test_initial_dashboard_counters_all_zero(self):
        """Req 1 & 2: Initial dashboard opening must have all 0 counters and no dataset stats."""
        resp = self.client.get("/api/dashboard/summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["has_data"])
        self.assertEqual(data["total_records"], 0)
        self.assertEqual(data["normal_events"], 0)
        self.assertEqual(data["threats_detected"], 0)
        self.assertEqual(data["invalid_records"], 0)

    def test_chatbot_before_analysis_explains_no_records(self):
        """Req 9 & Scenario 6: Chatbot before analysis states no records available."""
        resp = self.client.post("/api/assistant/chat", json={"query": "How many threats were detected in my latest analysis?"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("No Detection Records Available", data["reply"])
        self.assertEqual(data["category"], "Session Status: Awaiting Analysis")

    def test_upload_valid_network_traffic_csv(self):
        """Req 3, 4, 5: Upload valid network traffic, analyze with trained models, counts add up."""
        csv_content = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.85,0.20,0.10,0.05,0.70,0.80,0.75,0.05\n"
            "0.0925,0.9765,0.3905,0.6040,0.5797,0.5831,0.6330,0.6870\n"
        ).encode("utf-8")
        files = {"file": ("network_sample.csv", csv_content, "text/csv")}
        resp = self.client.post("/api/detect/upload", files=files)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["total_records"], 2)
        self.assertEqual(data["total_records"], data["normal_events"] + data["threats_detected"] + data["invalid_records"])
        self.assertGreaterEqual(data["threats_detected"], 1)
        self.assertGreaterEqual(data["normal_events"], 1)
        self.assertIn("known_threats", data)
        self.assertIn("unknown_anomalous", data)
        self.assertEqual(data["threats_detected"], data["known_threats"] + data["unknown_anomalous"])

        summary_resp = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary_resp.status_code, 200)
        summary = summary_resp.json()
        self.assertTrue(summary["has_data"])
        self.assertEqual(summary["total_records"], 2)

    def test_upload_invalid_csv_validation_error(self):
        """Scenario 4: Invalid CSV displays meaningful validation error and does not fabricate results."""
        invalid_csv = b"random_col_1,random_col_2\n123,456\n"
        files = {"file": ("malformed.csv", invalid_csv, "text/csv")}
        resp = self.client.post("/api/detect/upload", files=files)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("validation failed", resp.json()["detail"].lower())

    def test_chatbot_after_analysis_answers_with_actual_records(self):
        """Req 9 & Scenario 7: Chatbot after analysis answers using actual inference records."""
        csv_content = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.85,0.20,0.10,0.05,0.70,0.80,0.75,0.05\n"
        ).encode("utf-8")
        files = {"file": ("threat_sample.csv", csv_content, "text/csv")}
        self.client.post("/api/detect/upload", files=files)

        resp1 = self.client.post("/api/assistant/chat", json={"query": "How many threats were detected in my latest analysis?"})
        self.assertEqual(resp1.status_code, 200)
        reply1 = resp1.json()["reply"]
        self.assertIn("Total Records Analysed:", reply1)
        self.assertIn("threat_sample.csv", reply1)

        resp2 = self.client.post("/api/assistant/chat", json={"query": "Why was this network flow classified as suspicious?"})
        self.assertEqual(resp2.status_code, 200)
        self.assertIn("Threat Classification Explanation", resp2.json()["reply"])

        resp3 = self.client.post("/api/assistant/chat", json={"query": "What actions should I take for this threat?"})
        self.assertEqual(resp3.status_code, 200)
        self.assertIn("iptables", resp3.json()["reply"])

    def test_detection_history_contains_actual_records(self):
        """Req 6 & Scenario 9: Detection History contains actual inference records."""
        payload = {
            "source_ip": "172.16.0.1",
            "destination_ip": "192.168.10.50",
            "source_port": 50123,
            "destination_port": 21,
            "protocol": 6,
            "flow_duration": 3000.0,
            "flow_packets_s": 700000.0,
            "flow_bytes_s": 2500000.0,
            "syn_flag_count": 2,
            "flow_count": 20
        }
        self.client.post("/api/models/predict/flow", json=payload)
        resp = self.client.get("/api/history?limit=10")
        self.assertEqual(resp.status_code, 200)
        history = resp.json()
        self.assertGreaterEqual(len(history), 1)
        first = history[0]
        self.assertEqual(first["source_ip"], "172.16.0.1")
        self.assertEqual(first["destination_ip"], "192.168.10.50")
        self.assertEqual(first["destination_port"], 21)
        self.assertIn("model_breakdown", first)
        self.assertIn("dominant_basepoint", first)

    def test_floating_assistant_and_eight_sections_served(self):
        """Req 7 & 8: Floating AI button and modal + 8 sidebar sections served with Incident Response removed."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        text = resp.text
        self.assertIn("id=\"floatingChatBtn\"", text)
        self.assertIn("id=\"floatingChatPanel\"", text)
        self.assertIn("id=\"view-assistant\"", text)
        for view in [
            "view-dashboard", "view-analyzer", "view-profiles", "view-models",
            "view-anomaly", "view-history", "view-assistant", "view-about"
        ]:
            self.assertIn(f'id="{view}"', text)
        self.assertNotIn('id="view-incident"', text)
        self.assertNotIn('data-view="view-incident"', text)


if __name__ == "__main__":
    unittest.main()
