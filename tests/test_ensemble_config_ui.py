"""
Unit test suite verifying the simplified read-only Soft-Voting Ensemble Configuration card
and confirming removal of manual tuning sliders and buttons.
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app


class TestEnsembleConfigUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_manual_tuning_sliders_and_apply_button_removed(self):
        """Verifies that all 4 sliders and the apply button are completely removed from index.html."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        # Verify sliders removed
        self.assertNotIn("sliderWeightFcnn", html)
        self.assertNotIn("sliderWeightCnn", html)
        self.assertNotIn("sliderWeightLstm", html)
        self.assertNotIn("sliderThreshold", html)

        # Verify button removed
        self.assertNotIn("btnApplyEnsemble", html)
        self.assertNotIn("Apply Ensemble Parameters", html)

    def test_02_read_only_table_and_explanation_present(self):
        """Verifies the read-only table structure, semantic IDs, and exact explanation text."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        # Configuration table
        self.assertIn('id="tableEnsembleConfig"', html)
        self.assertIn('id="cfgFcnnWeight"', html)
        self.assertIn('id="cfgCnnWeight"', html)
        self.assertIn('id="cfgLstmWeight"', html)
        self.assertIn('id="cfgEnsembleThreshold"', html)
        self.assertIn('id="cfgIsoThreshold"', html)

        # Table rows
        self.assertIn("FCNN Weight", html)
        self.assertIn("CNN Weight", html)
        self.assertIn("LSTM Weight", html)
        self.assertIn("Ensemble Alert Threshold", html)
        self.assertIn("Isolation Forest Threshold", html)

        # Values
        self.assertIn("0.33", html)
        self.assertIn("0.6561", html)
        self.assertIn("-0.012676", html)

        # Exact explanation text
        explanation = (
            "The ensemble combines predictions from FCNN, CNN and LSTM using fixed calibrated weights. "
            "The alert threshold is derived from validation data. These settings are read-only to maintain consistent detection behaviour."
        )
        self.assertIn(explanation, html)

    def test_03_active_backend_config_matches(self):
        """Verifies that backend system status and anomaly overview provide matching active configuration."""
        status_resp = self.client.get("/api/status")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.json()

        ens_cfg = status_data.get("ensemble_config", {})
        self.assertIn("weights", ens_cfg)
        self.assertIn("threshold", ens_cfg)
        weights = ens_cfg["weights"]
        self.assertEqual(len(weights), 3)
        self.assertAlmostEqual(weights[0], 0.33, places=2)
        self.assertAlmostEqual(weights[1], 0.33, places=2)
        self.assertAlmostEqual(weights[2], 0.33, places=2)
        self.assertAlmostEqual(ens_cfg["threshold"], 0.6561, places=3)

        anomaly_resp = self.client.get("/api/anomaly/overview")
        self.assertEqual(anomaly_resp.status_code, 200)
        anomaly_data = anomaly_resp.json()
        self.assertAlmostEqual(anomaly_data["optimal_threshold"], -0.012676, places=5)

    def test_04_ensemble_and_isolation_forest_predictions_operational(self):
        """Verifies that ensemble inference and isolation forest anomaly evaluation remain fully operational."""
        payload = {
            "bp_01": 0.1, "bp_02": 0.2, "bp_03": 0.05, "bp_04": 0.8,
            "bp_05": 0.9, "bp_06": 0.01, "bp_07": 0.02, "bp_08": 0.03
        }
        resp = self.client.post("/api/models/predict/profile", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("verdict", data)
        self.assertIn("confidence", data)
        self.assertIn("threat_confidence", data)
        self.assertIn("threshold", data)
        self.assertIn("model_breakdown", data)
        self.assertIn("anomaly", data)
        self.assertIn("anomaly_score", data)
        self.assertIn("detection_reason", data)

        # Confirm all 3 submodels evaluated
        self.assertIn("fcnn", data["model_breakdown"])
        self.assertIn("cnn", data["model_breakdown"])
        self.assertIn("lstm", data["model_breakdown"])

    def test_05_app_js_cleaned_of_slider_tuning_code(self):
        """Verifies app.js has no dead slider event listener code or references to removed elements."""
        resp = self.client.get("/static/js/app.js")
        self.assertEqual(resp.status_code, 200)
        js = resp.text

        self.assertNotIn("sliderWeightFcnn", js)
        self.assertNotIn("sliderWeightCnn", js)
        self.assertNotIn("sliderWeightLstm", js)
        self.assertNotIn("sliderThreshold", js)
        self.assertNotIn("btnApplyEnsemble", js)
        self.assertNotIn("initEnsembleControls", js)

        # Check read-only sync logic exists
        self.assertIn("cfgEnsembleThreshold", js)
        self.assertIn("cfgFcnnWeight", js)
        self.assertIn("cfgIsoThreshold", js)


if __name__ == "__main__":
    unittest.main()
