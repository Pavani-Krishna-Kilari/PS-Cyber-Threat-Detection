"""
Unit and Integration Tests for Dual-Layer Data Drift Detection Engine.
Validates:
1. Exact mathematical calculations (PSI, KS, Wasserstein, JS Distance)
2. Layer 1 Network Feature Drift across verified 4 features
3. Layer 2 Event Profile Drift across bp_01..bp_08 and dominant basepoints
4. Overall Score calculation, equal 50/50 weighting, and partial omission handling
5. Threshold classification (LOW < 0.25, MODERATE 0.25..0.50, SIGNIFICANT >= 0.50)
6. Dynamic Training Dataset Update Recommendation alert trigger (>= 0.50)
7. Full vs Benign Reference Baselines
8. SQLite persistence and FastAPI REST endpoints
"""

import json
import math
import unittest
from pathlib import Path
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from backend.main import app
import backend.database as db
from src.drift.baseline import (
    load_reference_baseline,
    extract_distribution_summary,
    RAW_FEATURES,
    PROFILE_FEATURES,
)
from src.drift.engine import (
    DriftEngine,
    compute_psi,
    compute_ks,
    compute_wasserstein,
    compute_js_distance,
)


class TestDriftMathPrimitives(unittest.TestCase):
    """Tests the mathematical correctness and stability of statistical distance functions."""

    def test_psi_identical_distributions(self):
        # 11 decile edges
        ref_deciles = list(np.linspace(0, 100, 11))
        # Actual samples uniformly distributed across the same range
        actual = np.linspace(0, 100, 1000)
        psi, psi_score = compute_psi(actual, ref_deciles)
        self.assertGreaterEqual(psi, 0.0)
        self.assertLess(psi, 0.05)
        self.assertLess(psi_score, 0.10)

    def test_psi_shifted_distribution(self):
        ref_deciles = list(np.linspace(0, 100, 11))
        # Actual samples concentrated far outside the reference range
        actual = np.array([500.0] * 500)
        psi, psi_score = compute_psi(actual, ref_deciles)
        self.assertGreater(psi, 0.50)
        self.assertAlmostEqual(psi_score, 1.0, places=2)

    def test_psi_duplicate_bin_edges(self):
        # Reference distribution with repeated values (e.g., zero-inflated syn_flag_count)
        ref_deciles = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0]
        actual = np.array([0.0] * 80 + [1.0] * 20)
        psi, psi_score = compute_psi(actual, ref_deciles)
        self.assertGreaterEqual(psi, 0.0)
        self.assertGreaterEqual(psi_score, 0.0)
        self.assertLessEqual(psi_score, 1.0)

    def test_ks_identical_distribution(self):
        ref_quantiles = list(np.linspace(0, 100, 101))
        actual = np.linspace(0, 100, 1000)
        d_ks, p_val = compute_ks(actual, ref_quantiles)
        self.assertLess(d_ks, 0.05)
        self.assertGreater(p_val, 0.50)

    def test_ks_shifted_distribution(self):
        ref_quantiles = list(np.linspace(0, 100, 101))
        actual = np.linspace(200, 300, 1000)
        d_ks, p_val = compute_ks(actual, ref_quantiles)
        self.assertAlmostEqual(d_ks, 1.0, places=2)
        self.assertLess(p_val, 1e-4)

    def test_wasserstein_unit_interval(self):
        # Profile features are bounded in [0, 1]
        ref_quantiles = list(np.linspace(0, 1, 101))
        actual = np.linspace(0, 1, 1000)
        w_raw, w_norm, w_score = compute_wasserstein(actual, ref_quantiles, ref_iqr=0.5, is_bounded_unit_interval=True)
        self.assertLess(w_raw, 0.02)
        self.assertLess(w_score, 0.02)

    def test_wasserstein_normalized_continuous(self):
        ref_quantiles = list(np.linspace(10, 50, 101))
        actual = np.linspace(100, 150, 500)
        w_raw, w_norm, w_score = compute_wasserstein(actual, ref_quantiles, ref_iqr=10.0, is_bounded_unit_interval=False)
        self.assertGreater(w_raw, 50.0)
        self.assertGreater(w_norm, 5.0)
        self.assertGreaterEqual(w_score, 0.90)
        self.assertLessEqual(w_score, 1.0)

    def test_js_distance_identical_and_orthogonal(self):
        dist_a = {f"bp_{i:02d}": 1.0 / 8.0 for i in range(1, 9)}
        jsd_same, dist_same = compute_js_distance(dist_a, dist_a)
        self.assertAlmostEqual(jsd_same, 0.0, places=4)
        self.assertAlmostEqual(dist_same, 0.0, places=4)

        dist_b = {f"bp_{i:02d}": 0.0 for i in range(1, 9)}
        dist_b["bp_01"] = 1.0
        dist_c = {f"bp_{i:02d}": 0.0 for i in range(1, 9)}
        dist_c["bp_08"] = 1.0
        jsd_ortho, dist_ortho = compute_js_distance(dist_b, dist_c)
        self.assertGreater(jsd_ortho, 0.90)
        self.assertGreater(dist_ortho, 0.95)
        self.assertLessEqual(dist_ortho, 1.0)


class TestDriftEngineEvaluation(unittest.TestCase):
    """Tests complete Dual-Layer evaluation on simulated and reference data."""

    @classmethod
    def setUpClass(cls):
        cls.engine = DriftEngine()

    def test_reference_baseline_loaded(self):
        self.assertEqual(self.engine.experiment, "exp_b")
        self.assertIn("full_reference", self.engine.baseline)
        self.assertIn("benign_reference", self.engine.baseline)
        self.assertEqual(self.engine.baseline["n_training_flows"], 1614510)
        self.assertEqual(self.engine.baseline["n_training_profiles"], 1997495)

    def test_layer1_low_drift_on_training_distribution(self):
        # Sample synthetic flows matching reference quantiles
        ref_f = self.engine.full_ref["network_features"]
        simulated_flows = {}
        for feat in RAW_FEATURES:
            qs = ref_f[feat]["quantiles_100"]
            if feat == "syn_flag_count":
                p_syn = float(ref_f[feat]["mean"])
                simulated_flows[feat] = np.random.choice([0.0, 1.0], size=5000, p=[1.0 - p_syn, p_syn])
            else:
                simulated_flows[feat] = np.random.choice(qs, size=5000)

        df_sim = pd.DataFrame(simulated_flows)
        res = self.engine.evaluate_network_features(df_sim, population="full")
        self.assertEqual(res["n_evaluated_features"], 4)
        self.assertLess(res["score"], 0.25)
        for feat in RAW_FEATURES:
            self.assertIn(feat, res["features"])
            self.assertIn("psi", res["features"][feat])
            self.assertIn("ks_statistic", res["features"][feat])
            self.assertIn("wasserstein_normalized", res["features"][feat])

    def test_layer1_severe_drift(self):
        # Distort all features by 100x
        distorted_flows = {
            "flow_duration": np.full(500, 1e9),
            "flow_bytes_s": np.full(500, 1e9),
            "flow_packets_s": np.full(500, 1e9),
            "syn_flag_count": np.full(500, 50.0)
        }
        df_distorted = pd.DataFrame(distorted_flows)
        res = self.engine.evaluate_network_features(df_distorted, population="full")
        self.assertGreaterEqual(res["score"], 0.70)

    def test_layer2_low_drift_on_training_profiles(self):
        ref_p = self.engine.full_ref["event_profiles"]
        sim_profiles = np.zeros((2000, 8), dtype=np.float32)
        for idx, bp in enumerate(PROFILE_FEATURES):
            qs = ref_p[bp]["quantiles_100"]
            sim_profiles[:, idx] = np.random.choice(qs, size=2000)

        res = self.engine.evaluate_event_profiles(sim_profiles, population="full")
        self.assertLess(res["score"], 0.45)
        self.assertIn("basepoints", res)
        self.assertIn("js_distance", res)
        self.assertEqual(len(res["basepoints"]), 8)

    def test_overall_drift_complete_equal_weights(self):
        # Synthesize moderate flows and profiles
        df_flows = pd.DataFrame({
            "flow_duration": np.random.uniform(100, 10000, 200),
            "flow_bytes_s": np.random.uniform(1000, 50000, 200),
            "flow_packets_s": np.random.uniform(10, 500, 200),
            "syn_flag_count": np.random.choice([0, 1], 200)
        })
        profiles = np.random.dirichlet(np.ones(8), size=100)

        rep = self.engine.evaluate_drift(
            df_flows=df_flows,
            profiles_matrix=profiles,
            session_id="SESS-TEST-01"
        )
        self.assertFalse(rep["is_partial"])
        self.assertIsNone(rep["omitted_layer"])
        expected_score = round(0.5 * rep["layer1_network_features"]["score"] + 0.5 * rep["layer2_event_profiles"]["score"], 4)
        self.assertAlmostEqual(rep["overall_drift_score"], expected_score, places=3)
        self.assertIn(rep["drift_status"], ("LOW", "MODERATE", "SIGNIFICANT"))

    def test_partial_mode_profiles_only(self):
        # Preaggregated profile CSV scenario
        profiles = np.random.dirichlet(np.ones(8), size=100)
        rep = self.engine.evaluate_drift(df_flows=None, profiles_matrix=profiles)
        self.assertTrue(rep["is_partial"])
        self.assertEqual(rep["omitted_layer"], "Layer 1: Network Features")
        self.assertIsNone(rep["layer1_network_features"])
        self.assertEqual(rep["overall_drift_score"], rep["layer2_event_profiles"]["score"])

    def test_partial_mode_flows_only(self):
        df_flows = pd.DataFrame({
            "flow_duration": np.random.uniform(100, 10000, 200),
            "flow_bytes_s": np.random.uniform(1000, 50000, 200),
            "flow_packets_s": np.random.uniform(10, 500, 200),
            "syn_flag_count": np.random.choice([0, 1], 200)
        })
        rep = self.engine.evaluate_drift(df_flows=df_flows, profiles_matrix=None)
        self.assertTrue(rep["is_partial"])
        self.assertEqual(rep["omitted_layer"], "Layer 2: Event Profiles")
        self.assertIsNone(rep["layer2_event_profiles"])
        self.assertEqual(rep["overall_drift_score"], rep["layer1_network_features"]["score"])

    def test_significant_drift_recommendation_alert(self):
        # Heavily drifted flows and profiles
        df_flows = pd.DataFrame({
            "flow_duration": np.full(200, 999999999.0),
            "flow_bytes_s": np.full(200, 999999999.0),
            "flow_packets_s": np.full(200, 999999999.0),
            "syn_flag_count": np.full(200, 100.0)
        })
        # Orthogonal profile: all weight on bp_08 where reference has 0.0001
        profiles = np.zeros((100, 8))
        profiles[:, 7] = 1.0

        rep = self.engine.evaluate_drift(df_flows=df_flows, profiles_matrix=profiles)
        self.assertGreaterEqual(rep["overall_drift_score"], 0.50)
        self.assertEqual(rep["drift_status"], "SIGNIFICANT")
        self.assertTrue(rep["recommendation_alert"])
        self.assertIn("strongly recommended", rep["recommendation_message"].lower())


class TestDatabaseAndAPIIntegration(unittest.TestCase):
    """Tests SQLite persistence and FastAPI REST endpoints for drift reports."""

    def setUp(self):
        self.client = TestClient(app)
        self.test_session_id = f"SESS-DRIFT-TEST-{np.random.randint(10000, 99999)}"
        from backend.auth import authenticate_operator
        auth = authenticate_operator("admin@soc.ai", "CyberShield2026!")
        self.admin_headers = {"Authorization": f"Bearer {auth['session_token']}"}

    def tearDown(self):
        # Clean up test session
        db.delete_session(self.test_session_id)

    def test_drift_report_crud_and_endpoints(self):
        # Verify unauthenticated requests return 401 Unauthorized
        res_unauth = self.client.get("/api/drift/latest")
        self.assertEqual(res_unauth.status_code, 401)

        # 1. Save dummy drift report
        dummy_report = {
            "session_id": self.test_session_id,
            "upload_id": "UPL-TEST-001",
            "reference_experiment": "exp_b",
            "reference_population": "full",
            "overall_drift_score": 0.5842,
            "overall_drift_percentage": 58.42,
            "drift_status": "SIGNIFICANT",
            "recommendation_alert": True,
            "recommendation_message": "Significant drift detected. Training dataset update recommended.",
            "is_partial": False,
            "omitted_layer": "",
            "layer1_network_features": {"score": 0.6120},
            "layer2_event_profiles": {"score": 0.5564}
        }

        # Also create parent analysis_session so foreign key is valid
        db.insert_session({
            "session_id": self.test_session_id,
            "source_name": "test_drift_file.csv",
            "total_records": 1000,
            "drift_analysis": dummy_report
        })

        # Query latest drift endpoint with Head of SOC authorization
        res_latest = self.client.get("/api/drift/latest", headers=self.admin_headers)
        self.assertEqual(res_latest.status_code, 200)
        data_latest = res_latest.json()
        self.assertTrue(data_latest["has_drift"])
        self.assertEqual(data_latest["report"]["session_id"], self.test_session_id)
        self.assertEqual(data_latest["report"]["drift_status"], "SIGNIFICANT")

        # Query history endpoint with Head of SOC authorization
        res_hist = self.client.get("/api/drift/history?limit=10", headers=self.admin_headers)
        self.assertEqual(res_hist.status_code, 200)
        hist = res_hist.json()
        self.assertIsInstance(hist, list)
        self.assertGreaterEqual(len(hist), 1)
        match = next((item for item in hist if item["session_id"] == self.test_session_id), None)
        self.assertIsNotNone(match)
        self.assertEqual(match["drift_status"], "SIGNIFICANT")

        # Query session-specific drift endpoint with Head of SOC authorization
        res_sess = self.client.get(f"/api/sessions/{self.test_session_id}/drift", headers=self.admin_headers)
        self.assertEqual(res_sess.status_code, 200)
        data_sess = res_sess.json()
        self.assertEqual(data_sess["session_id"], self.test_session_id)
        self.assertEqual(data_sess["overall_drift_percentage"], 58.42)

        # Query reference baseline summary endpoint with Head of SOC authorization
        res_ref = self.client.get("/api/drift/reference", headers=self.admin_headers)
        self.assertEqual(res_ref.status_code, 200)
        ref_data = res_ref.json()
        self.assertEqual(ref_data["experiment"], "exp_b")
        self.assertEqual(ref_data["n_training_flows"], 1614510)


if __name__ == "__main__":
    unittest.main()
