"""
Comprehensive unit and integration tests for Role-Based Data Drift and Training Dataset Management.

Verifies:
1. Two user roles: Regular Security Analyst and Head of SOC.
2. Regular Security Analyst permissions and strict 403 rejection on Data Drift and Training APIs.
3. Head of SOC full access to Data Drift, Candidate Studio, dataset validation, candidate training, activation, and rollback.
4. Session report drift redaction for Regular Security Analyst while visible to Head of SOC.
5. Schema and quality validation for candidate training datasets.
6. Isolated sandbox candidate training without modifying baseline model weights.
7. Supervisory authorization for candidate model activation with automated backups.
8. Model rollback capability restoring the baseline model.
9. Preservation of protected forensic upload incident UPL-20261118220457-b41aa8a7.

Run with:
    python -m unittest tests.test_role_based_access -v
"""

import io
import json
import os
import uuid
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from src.config import PROJECT_ROOT
from backend.main import app
from backend.auth import (
    ROLE_HEAD_OF_SOC,
    ROLE_SECURITY_ANALYST,
    SOC_OPERATORS,
    authenticate_operator,
)
import backend.database as db
import backend.training_manager as tm


class TestRoleBasedAccessControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.admin_email = "admin@soc.ai"
        cls.admin_password = "CyberShield2026!"
        cls.analyst_email = "analyst@soc.ai"
        cls.analyst_password = "ThreatHunter2026!"

        # Authenticate Head of SOC
        admin_auth = authenticate_operator(cls.admin_email, cls.admin_password)
        cls.admin_token = admin_auth["session_token"]
        cls.admin_user = admin_auth["user"]

        # Authenticate Regular Security Analyst
        analyst_auth = authenticate_operator(cls.analyst_email, cls.analyst_password)
        cls.analyst_token = analyst_auth["session_token"]
        cls.analyst_user = analyst_auth["user"]

    def test_01_user_roles_and_permissions(self):
        """Verify role IDs and permissions assigned upon authentication."""
        self.assertEqual(self.admin_user["role_id"], ROLE_HEAD_OF_SOC)
        self.assertEqual(self.admin_user["role"], "Head of SOC")
        self.assertIn("view_drift", self.admin_user["permissions"])
        self.assertIn("manage_training_datasets", self.admin_user["permissions"])
        self.assertIn("train_candidate_models", self.admin_user["permissions"])
        self.assertIn("activate_models", self.admin_user["permissions"])

        self.assertEqual(self.analyst_user["role_id"], ROLE_SECURITY_ANALYST)
        self.assertEqual(self.analyst_user["role"], "Regular Security Analyst")
        self.assertNotIn("view_drift", self.analyst_user["permissions"])
        self.assertNotIn("manage_training_datasets", self.analyst_user["permissions"])
        self.assertNotIn("train_candidate_models", self.analyst_user["permissions"])
        self.assertNotIn("activate_models", self.analyst_user["permissions"])

    def test_02_analyst_blocked_from_drift_endpoints(self):
        """Regular Security Analyst must receive HTTP 403 on all drift endpoints."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}

        # GET /api/drift/latest
        res = self.client.get("/api/drift/latest", headers=headers)
        self.assertEqual(res.status_code, 403, f"Expected 403, got {res.status_code}: {res.text}")

        # GET /api/drift/history
        res = self.client.get("/api/drift/history", headers=headers)
        self.assertEqual(res.status_code, 403)

        # GET /api/drift/reference
        res = self.client.get("/api/drift/reference", headers=headers)
        self.assertEqual(res.status_code, 403)

        # GET /api/sessions/SES-TEST/drift
        res = self.client.get("/api/sessions/SES-TEST/drift", headers=headers)
        self.assertEqual(res.status_code, 403)

    def test_03_analyst_blocked_from_training_studio_endpoints(self):
        """Regular Security Analyst must receive HTTP 403 on all training candidate studio endpoints."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}

        # GET /api/training/studio/overview
        res = self.client.get("/api/training/studio/overview", headers=headers)
        self.assertEqual(res.status_code, 403)

        # POST /api/training/dataset/validate
        res = self.client.post(
            "/api/training/dataset/validate",
            headers=headers,
            files={"file": ("test.csv", b"col1,col2\n1,2", "text/csv")},
        )
        self.assertEqual(res.status_code, 403)

        # POST /api/training/dataset/upload
        res = self.client.post(
            "/api/training/dataset/upload",
            headers=headers,
            files={"file": ("test.csv", b"col1,col2\n1,2", "text/csv")},
        )
        self.assertEqual(res.status_code, 403)

        # POST /api/training/candidate/train
        res = self.client.post(
            "/api/training/candidate/train",
            headers=headers,
            json={"dataset_id": "DS-TEST"},
        )
        self.assertEqual(res.status_code, 403)

        # POST /api/training/candidate/MDL-TEST/activate
        res = self.client.post(
            "/api/training/candidate/MDL-TEST/activate",
            headers=headers,
            json={"approval_note": "Analyst attempt"},
        )
        self.assertEqual(res.status_code, 403)

        # POST /api/training/candidate/rollback
        res = self.client.post(
            "/api/training/candidate/rollback",
            headers=headers,
            json={"rollback_note": "Analyst attempt"},
        )
        self.assertEqual(res.status_code, 403)

    def test_04_unauthenticated_requests_rejected(self):
        """Unauthenticated requests to drift and training endpoints must return HTTP 401."""
        # Drift endpoints must strictly return HTTP 401
        self.assertEqual(self.client.get("/api/drift/latest").status_code, 401)
        self.assertEqual(self.client.get("/api/drift/history").status_code, 401)
        self.assertEqual(self.client.get("/api/drift/reference").status_code, 401)
        self.assertEqual(self.client.get("/api/sessions/SES-TEST/drift").status_code, 401)

        # Training studio endpoints must strictly return HTTP 401
        res = self.client.get("/api/training/studio/overview")
        self.assertEqual(res.status_code, 401)

        res = self.client.post(
            "/api/training/dataset/validate",
            files={"file": ("test.csv", b"col1,col2\n1,2", "text/csv")},
        )
        self.assertEqual(res.status_code, 401)

        res = self.client.post(
            "/api/training/candidate/train",
            json={"dataset_id": "DS-TEST"},
        )
        self.assertEqual(res.status_code, 401)

    def test_05_head_of_soc_permitted_drift_and_studio(self):
        """Head of SOC must be granted access to drift and training studio endpoints."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # GET /api/drift/latest
        res = self.client.get("/api/drift/latest", headers=headers)
        self.assertEqual(res.status_code, 200)

        # GET /api/drift/history
        res = self.client.get("/api/drift/history", headers=headers)
        self.assertEqual(res.status_code, 200)

        # GET /api/drift/reference
        res = self.client.get("/api/drift/reference", headers=headers)
        self.assertEqual(res.status_code, 200)

        # GET /api/training/studio/overview
        res = self.client.get("/api/training/studio/overview", headers=headers)
        self.assertEqual(res.status_code, 200)
        overview = res.json()
        self.assertIn("active_model", overview)
        self.assertIn("candidates", overview)
        self.assertIn("backups", overview)

    def test_06_session_report_drift_filtering_by_role(self):
        """Session report must strip drift_analysis for Regular Security Analyst but include it for Head of SOC."""
        # Find or create a session in database with drift analysis
        latest_drift = db.get_latest_drift_report()
        if latest_drift and latest_drift.get("session_id"):
            session_id = latest_drift["session_id"]
        else:
            # Create a mock session report with drift
            session_id = "SES-RBAC-DRIFT-TEST"
            db.save_session_report({
                "session_id": session_id,
                "upload_id": "UPL-RBAC-TEST",
                "filename": "rbac_test.csv",
                "total_records": 100,
                "total_processed": 10,
                "known_threats": 1,
                "unknown_anomalous": 0,
                "timestamp": "2026-11-20T12:00:00"
            })
            db.save_drift_report({
                "session_id": session_id,
                "upload_id": "UPL-RBAC-TEST",
                "overall_drift_score": 0.15,
                "overall_drift_percentage": 15.0,
                "drift_status": "LOW",
                "layer1_score": 0.10,
                "layer2_score": 0.20,
                "is_partial": False,
                "report_json": {"overall_drift_score": 0.15}
            })

        # 1. Head of SOC requests session report -> drift_analysis is present
        admin_res = self.client.get(
            f"/api/sessions/{session_id}",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(admin_res.status_code, 200)
        admin_data = admin_res.json()
        self.assertIsNotNone(admin_data.get("drift_analysis"))

        # 2. Regular Analyst requests same session report -> drift_analysis is None / omitted
        analyst_res = self.client.get(
            f"/api/sessions/{session_id}",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(analyst_res.status_code, 200)
        analyst_data = analyst_res.json()
        self.assertIsNone(analyst_data.get("drift_analysis"))

        # 3. Unauthenticated request to session report -> drift_analysis is None / omitted
        unauth_res = self.client.get(f"/api/sessions/{session_id}")
        self.assertEqual(unauth_res.status_code, 200)
        unauth_data = unauth_res.json()
        self.assertIsNone(unauth_data.get("drift_analysis"))

    def test_07_candidate_dataset_validation(self):
        """Validate candidate dataset schema detection, label checks, and quality thresholds."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # Case A: Invalid garbage CSV
        bad_csv = b"col_a,col_b\n1,2\n3,4\n"
        res = self.client.post(
            "/api/training/dataset/validate",
            headers=headers,
            files={"file": ("bad_dataset.csv", bad_csv, "text/csv")},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data["is_valid"])
        self.assertTrue(len(data["issues"]) > 0)

        # Case B: Valid event profiles CSV with 8 basepoints and binary label
        cols = [f"bp_0{i}" for i in range(1, 9)] + ["label"]
        rows = [",".join(cols)]
        for i in range(50):
            # 25 benign (0.1..0.3), 25 attack (0.7..0.9)
            val = 0.2 if i < 25 else 0.8
            lbl = "BENIGN" if i < 25 else "ATTACK"
            rows.append(",".join([f"{val + (j*0.01):.4f}" for j in range(8)] + [lbl]))

        valid_csv = "\n".join(rows).encode("utf-8")
        res = self.client.post(
            "/api/training/dataset/validate",
            headers=headers,
            files={"file": ("valid_profiles.csv", valid_csv, "text/csv")},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["is_valid"])
        self.assertEqual(data["schema_type"], "EVENT_PROFILES")
        self.assertEqual(data["num_rows"], 50)
        self.assertEqual(data["class_balance"]["BENIGN"], 25)
        self.assertEqual(data["class_balance"]["ATTACK"], 25)

    def test_08_candidate_model_training_and_lifecycle(self):
        """Test candidate dataset upload, isolated model training, evaluation metrics, activation, and rollback."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Upload valid candidate dataset
        cols = [f"bp_0{i}" for i in range(1, 9)] + ["label"]
        rows = [",".join(cols)]
        for i in range(100):
            val = 0.15 if i < 50 else 0.85
            lbl = "BENIGN" if i < 50 else "ATTACK"
            rows.append(",".join([f"{val + (j*0.01):.4f}" for j in range(8)] + [lbl]))

        valid_csv = "\n".join(rows).encode("utf-8")
        upload_res = self.client.post(
            "/api/training/dataset/upload",
            headers=headers,
            files={"file": ("test_candidate_dataset.csv", valid_csv, "text/csv")},
        )
        self.assertEqual(upload_res.status_code, 200)
        dataset_entry = upload_res.json()["dataset"]
        dataset_id = dataset_entry["dataset_id"]
        self.assertTrue(dataset_id.startswith("DS-CAND-"))

        # 2. Train isolated candidate model
        train_res = self.client.post(
            "/api/training/candidate/train",
            headers=headers,
            json={"dataset_id": dataset_id},
        )
        self.assertEqual(train_res.status_code, 200)
        candidate = train_res.json()["candidate"]
        candidate_id = candidate["candidate_id"]
        self.assertTrue(candidate_id.startswith("MDL-CAND-"))
        self.assertEqual(candidate["status"], "TRAINED")

        # Verify evaluation metrics structure
        metrics = candidate["metrics"]
        self.assertIn("precision", metrics)
        self.assertIn("recall", metrics)
        self.assertIn("f1_score", metrics)
        self.assertIn("pr_auc", metrics)
        self.assertIn("roc_auc", metrics)
        self.assertIn("false_positive_rate", metrics)
        self.assertIn("confusion_matrix", metrics)
        cm = metrics["confusion_matrix"]
        self.assertIn("true_positives", cm)
        self.assertIn("true_negatives", cm)
        self.assertIn("false_positives", cm)
        self.assertIn("false_negatives", cm)

        # Verify active baseline weights are intact
        baseline_model_path = PROJECT_ROOT / "models" / "saved_exp_b" / "fcnn_model.keras"
        self.assertTrue(baseline_model_path.exists())

        # 3. Regular Analyst cannot activate candidate model
        analyst_headers = {"Authorization": f"Bearer {self.analyst_token}"}
        forbidden_act = self.client.post(
            f"/api/training/candidate/{candidate_id}/activate",
            headers=analyst_headers,
            json={"approval_note": "Unauthorized analyst attempt"},
        )
        self.assertEqual(forbidden_act.status_code, 403)

        # 4. Head of SOC authorizes and activates candidate model
        act_res = self.client.post(
            f"/api/training/candidate/{candidate_id}/activate",
            headers=headers,
            json={"approval_note": "Approved by Head of SOC after distribution verification"},
        )
        self.assertEqual(act_res.status_code, 200)
        act_data = act_res.json()
        self.assertEqual(act_data["status"], "SUCCESS")
        self.assertTrue(act_data["backup_id"].startswith("BKP-"))

        # Verify candidate model is now ACTIVE in database
        active_cand = db.get_active_candidate_model()
        self.assertIsNotNone(active_cand)
        self.assertEqual(active_cand["candidate_id"], candidate_id)

        # 5. Head of SOC triggers rollback
        rb_res = self.client.post(
            "/api/training/candidate/rollback",
            headers=headers,
            json={"rollback_note": "Rolling back to baseline after test verification"},
        )
        self.assertEqual(rb_res.status_code, 200)
        rb_data = rb_res.json()
        self.assertEqual(rb_data["status"], "SUCCESS")

        # Verify active candidate model is reverted
        active_after_rb = db.get_active_candidate_model()
        self.assertIsNone(active_after_rb)

        cand_record = db.get_candidate_model(candidate_id)
        self.assertEqual(cand_record["status"], "ROLLED_BACK")

    def test_09_preservation_of_protected_upload(self):
        """Verify protected forensic upload incident UPL-20261118220457-b41aa8a7 remains intact."""
        protected_upload = db.get_upload("UPL-20261118220457-b41aa8a7")
        self.assertIsNotNone(protected_upload, "Protected upload UPL-20261118220457-b41aa8a7 must exist in database")
        self.assertEqual(protected_upload.get("upload_id"), "UPL-20261118220457-b41aa8a7")

    def test_10_dataset_validation_safeguards_data_types_nan_inf_empty(self):
        """TASK 2: Verify validation rejects empty files, incompatible types, NaNs, Infs, and single-class datasets."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Empty dataset (0 bytes)
        res_empty = self.client.post(
            "/api/training/dataset/validate",
            headers=headers,
            files={"file": ("empty.csv", b"", "text/csv")}
        )
        self.assertEqual(res_empty.status_code, 200)
        self.assertFalse(res_empty.json()["is_valid"])

        # 2. Incompatible non-numeric string in feature column
        cols = [f"bp_0{i}" for i in range(1, 9)] + ["label"]
        rows = [",".join(cols)]
        for i in range(30):
            val = "INVALID_STR" if i == 5 else f"{0.2 if i < 15 else 0.8:.4f}"
            lbl = "BENIGN" if i < 15 else "ATTACK"
            rows.append(",".join([val] + [f"{0.2 if i < 15 else 0.8:.4f}"] * 7 + [lbl]))
        res_bad_type = self.client.post(
            "/api/training/dataset/validate",
            headers=headers,
            files={"file": ("bad_type.csv", "\n".join(rows).encode("utf-8"), "text/csv")}
        )
        self.assertEqual(res_bad_type.status_code, 200)
        data_bad_type = res_bad_type.json()
        self.assertFalse(data_bad_type["is_valid"])
        self.assertGreater(data_bad_type["rejected_rows"]["count"], 0)

        # 3. NaN / null values in feature column (must NOT silently impute)
        rows_nan = [",".join(cols)]
        for i in range(30):
            val = "" if i == 7 else f"{0.2 if i < 15 else 0.8:.4f}"
            lbl = "BENIGN" if i < 15 else "ATTACK"
            rows_nan.append(",".join([val] + [f"{0.2 if i < 15 else 0.8:.4f}"] * 7 + [lbl]))
        res_nan = self.client.post(
            "/api/training/dataset/validate",
            headers=headers,
            files={"file": ("nan_dataset.csv", "\n".join(rows_nan).encode("utf-8"), "text/csv")}
        )
        self.assertEqual(res_nan.status_code, 200)
        self.assertFalse(res_nan.json()["is_valid"])
        self.assertGreater(res_nan.json()["rejected_rows"]["count"], 0)

        # 4. Single-class dataset (only Benign, 0 attack samples)
        rows_single = [",".join(cols)]
        for i in range(30):
            rows_single.append(",".join([f"{0.2:.4f}"] * 8 + ["BENIGN"]))
        res_single = self.client.post(
            "/api/training/dataset/validate",
            headers=headers,
            files={"file": ("single_class.csv", "\n".join(rows_single).encode("utf-8"), "text/csv")}
        )
        self.assertEqual(res_single.status_code, 200)
        self.assertFalse(res_single.json()["is_valid"])
        self.assertTrue(any("Single-class" in str(iss) for iss in res_single.json()["issues"]))

    def test_11_training_safeguards_unpersisted_and_invalid_dataset(self):
        """TASK 1: Verify training requires a successfully persisted, valid dataset."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Non-existent dataset ID
        res_missing = self.client.post(
            "/api/training/candidate/train",
            headers=headers,
            json={"dataset_id": "DS-DOES-NOT-EXIST-9999"}
        )
        self.assertEqual(res_missing.status_code, 400)

        # 2. Persisting an invalid dataset must be rejected by backend
        bad_csv = b"col_x,col_y\n1,2\n"
        res_upload_bad = self.client.post(
            "/api/training/dataset/upload",
            headers=headers,
            files={"file": ("invalid_dataset.csv", bad_csv, "text/csv")}
        )
        self.assertEqual(res_upload_bad.status_code, 400)

    def test_12_activation_safeguards_missing_and_corrupt_artifacts(self):
        """TASK 4: Do not allow invalid, incomplete, or missing candidate artifacts to be activated."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Candidate ID does not exist
        res_missing = self.client.post(
            "/api/training/candidate/MDL-NONEXISTENT-999/activate",
            headers=headers,
            json={"approval_note": "Test activation"}
        )
        self.assertEqual(res_missing.status_code, 400)

        # 2. Candidate record exists in DB but artifact file on disk is deleted / missing
        dummy_cid = f"MDL-CAND-TEST-MISSING-{uuid.uuid4().hex[:6]}"
        db.save_candidate_model({
            "candidate_id": dummy_cid,
            "dataset_id": "DS-TEST",
            "model_name": "Test Missing Artifact",
            "status": "TRAINED",
            "metrics": {"f1_score": 0.95},
            "artifact_path": str(PROJECT_ROOT / "models" / "candidates" / dummy_cid / "missing_model.joblib")
        })
        res_act_missing = self.client.post(
            f"/api/training/candidate/{dummy_cid}/activate",
            headers=headers,
            json={"approval_note": "Activating missing artifact"}
        )
        self.assertEqual(res_act_missing.status_code, 400)

    def test_13_audit_trail_and_backup_verification(self):
        """TASK 4: Verify verified backup creation with SHA-256 and full audit trail fields."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # Upload dataset and train candidate
        cols = [f"bp_0{i}" for i in range(1, 9)] + ["label"]
        rows = [",".join(cols)]
        for i in range(60):
            val = 0.2 if i < 30 else 0.8
            lbl = "BENIGN" if i < 30 else "ATTACK"
            rows.append(",".join([f"{val + (j*0.01):.4f}" for j in range(8)] + [lbl]))

        upload_res = self.client.post(
            "/api/training/dataset/upload",
            headers=headers,
            files={"file": ("audit_test_dataset.csv", "\n".join(rows).encode("utf-8"), "text/csv")},
        )
        self.assertEqual(upload_res.status_code, 200)
        dataset_id = upload_res.json()["dataset"]["dataset_id"]

        train_res = self.client.post(
            "/api/training/candidate/train",
            headers=headers,
            json={"dataset_id": dataset_id},
        )
        self.assertEqual(train_res.status_code, 200)
        candidate_id = train_res.json()["candidate"]["candidate_id"]

        # Activate candidate
        act_res = self.client.post(
            f"/api/training/candidate/{candidate_id}/activate",
            headers=headers,
            json={"approval_note": "Audit verification activation test"},
        )
        self.assertEqual(act_res.status_code, 200)
        act_data = act_res.json()
        backup_id = act_data["backup_id"]

        # Verify backup manifest on disk
        backup_dir = PROJECT_ROOT / "models" / "backups" / backup_id
        manifest_file = backup_dir / "manifest.json"
        self.assertTrue(manifest_file.exists(), f"Backup manifest {manifest_file} must exist.")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(manifest["backup_id"], backup_id)
        self.assertEqual(manifest["verification_status"], "VERIFIED")
        self.assertTrue(len(manifest["sha256"]) > 0)

        # Verify audit trail in SQLite
        audits = db.list_activation_audits(limit=10)
        match = next((a for a in audits if a.get("candidate_id") == candidate_id and a.get("action") == "ACTIVATE"), None)
        self.assertIsNotNone(match, "Activation audit entry must exist in database")
        self.assertEqual(match["candidate_id"], candidate_id)
        self.assertEqual(match["dataset_id"], dataset_id)
        self.assertEqual(match["approved_by"], "admin@soc.ai")
        self.assertEqual(match["activation_result"], "SUCCESS")
        self.assertIn("f1_score", match.get("metrics", {}))

        # Rollback to baseline and verify active model restored
        rb_res = self.client.post(
            "/api/training/candidate/rollback",
            headers=headers,
            json={"rollback_note": "Rollback test"},
        )
        self.assertEqual(rb_res.status_code, 200)
        self.assertIsNone(db.get_active_candidate_model())

    def test_14_candidate_training_on_raw_network_flows_with_sliding_window_aggregation(self):
        """Verify complete event-profile generation pipeline and neural training on raw network flows."""
        import pandas as pd
        import numpy as np

        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Synthesize 30 raw network flows spanning 30 minutes (timestamps 60s apart)
        dates = pd.date_range("2026-11-20 08:00:00", periods=30, freq="60s")
        flow_df = pd.DataFrame({
            "source_ip": ["192.168.1.10"] * 30,
            "destination_ip": ["10.0.0.1"] * 30,
            "timestamp": [str(d) for d in dates],
            "flow_duration": np.random.randint(100, 1000, 30),
            "flow_packets_s": np.random.rand(30) * 10,
            "flow_bytes_s": np.random.rand(30) * 500,
            "syn_flag_count": np.random.randint(0, 2, 30),
            "label": ["BENIGN"] * 20 + ["ATTACK"] * 10
        })
        flow_csv = flow_df.to_csv(index=False).encode("utf-8")

        # Validate raw flows
        val_res = self.client.post(
            "/api/training/dataset/validate",
            headers=headers,
            files={"file": ("raw_flows.csv", flow_csv, "text/csv")},
        )
        self.assertEqual(val_res.status_code, 200)
        val_data = val_res.json()
        self.assertTrue(val_data["is_valid"])
        self.assertEqual(val_data["schema_type"], "NETWORK_FLOWS")

        # Upload and persist raw flows dataset
        up_res = self.client.post(
            "/api/training/dataset/upload",
            headers=headers,
            files={"file": ("raw_flows.csv", flow_csv, "text/csv")},
        )
        self.assertEqual(up_res.status_code, 200)
        dataset_id = up_res.json()["dataset"]["dataset_id"]

        # Train candidate model from raw flows -> invokes RawFlowAggregator
        train_res = self.client.post(
            "/api/training/candidate/train",
            headers=headers,
            json={"dataset_id": dataset_id},
        )
        self.assertEqual(train_res.status_code, 200)
        cand_data = train_res.json()["candidate"]
        self.assertTrue(cand_data["candidate_id"].startswith("MDL-CAND-"))
        self.assertEqual(cand_data["status"], "TRAINED")

        # Verify evaluation metrics
        metrics = cand_data["metrics"]
        self.assertIn("f1_score", metrics)
        self.assertIn("model_breakdown", metrics)
        self.assertIn("FCNN", metrics["model_breakdown"])
        self.assertIn("CNN", metrics["model_breakdown"])
        self.assertIn("LSTM", metrics["model_breakdown"])
        self.assertIn("submodel_thresholds", metrics)

    def test_15_dashboard_summary_drift_redacted_for_analyst(self):
        """Dashboard summary must redact drift_analysis for Regular Security Analyst and unauthenticated users."""
        from backend.service import siem_service
        orig_summary = siem_service.current_analysis_summary
        try:
            # Stage an active analysis summary containing drift_analysis
            siem_service.current_analysis_summary = {
                "has_data": True,
                "total_records": 100,
                "normal_events": 90,
                "threats_detected": 10,
                "drift_analysis": {
                    "overall_drift_score": 0.18,
                    "overall_drift_percentage": 18.0,
                    "drift_status": "MODERATE"
                }
            }

            # 1. Head of SOC receives drift_analysis
            admin_res = self.client.get(
                "/api/dashboard/summary",
                headers={"Authorization": f"Bearer {self.admin_token}"}
            )
            self.assertEqual(admin_res.status_code, 200)
            self.assertIsNotNone(admin_res.json().get("drift_analysis"))
            self.assertEqual(admin_res.json()["drift_analysis"]["overall_drift_percentage"], 18.0)

            # 2. Regular Security Analyst has drift_analysis completely stripped
            analyst_res = self.client.get(
                "/api/dashboard/summary",
                headers={"Authorization": f"Bearer {self.analyst_token}"}
            )
            self.assertEqual(analyst_res.status_code, 200)
            self.assertIsNone(analyst_res.json().get("drift_analysis"))
            self.assertNotIn("drift_analysis", analyst_res.json())

            # 3. Unauthenticated caller has drift_analysis completely stripped
            unauth_res = self.client.get("/api/dashboard/summary")
            self.assertEqual(unauth_res.status_code, 200)
            self.assertIsNone(unauth_res.json().get("drift_analysis"))
            self.assertNotIn("drift_analysis", unauth_res.json())
        finally:
            siem_service.current_analysis_summary = orig_summary


if __name__ == "__main__":
    unittest.main()
