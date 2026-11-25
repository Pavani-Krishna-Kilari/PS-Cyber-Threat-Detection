"""
Unit and Integration Tests for Render Cloud Deployment Readiness and Local Windows Compatibility.

Validates:
1. Default local data directory vs custom SOC_DATA_DIR resolution.
2. Database path resolution and schema initialization under SOC_DATA_DIR.
3. Target database is never overwritten during migration.
4. SQLite Connection.backup() migration preserves table structure, indexes, and records.
5. Failed migration does not leave a misleading partial database or temporary files.
6. WAL-mode source databases are handled safely with read-only connection.
7. Temporary tests do not access or modify the original detection database.
8. Upload directory and chunked staging path resolution under SOC_DATA_DIR.
9. Candidate datasets, candidate models, and model backup directory resolution.
10. Authentication security: demo accounts disabled when SOC_ENV=production.
11. Audit security: password recovery logging masks raw token.
12. Password recovery operations in tests use isolated temporary databases.
13. Immutable model artifacts and drift reference baseline availability.
14. Application startup initialization hook.
15. Runtime inference pipeline preservation (FCNN, CNN, LSTM, Isolation Forest).
"""

import io
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from src.config import PROJECT_ROOT, get_soc_data_dir
import backend.database as db
import backend.uploader as uploader
import backend.training_manager as tm
import backend.auth as auth
from backend.main import app
from backend.service import siem_service


class TestRenderDeployment(unittest.TestCase):
    REAL_DB_PATH = PROJECT_ROOT / "data" / "detection_history.db"

    @classmethod
    def setUpClass(cls):
        # Record initial baseline state of the real database
        if cls.REAL_DB_PATH.exists():
            stat = cls.REAL_DB_PATH.stat()
            cls.real_db_initial_size = stat.st_size
            cls.real_db_initial_mtime = stat.st_mtime
        else:
            cls.real_db_initial_size = 0
            cls.real_db_initial_mtime = 0

    @classmethod
    def tearDownClass(cls):
        # Assert the real database was never touched or modified during the entire test class run
        if cls.REAL_DB_PATH.exists():
            stat = cls.REAL_DB_PATH.stat()
            assert stat.st_size == cls.real_db_initial_size, (
                f"CRITICAL REGRESSION: Real database size modified! Was {cls.real_db_initial_size}, now {stat.st_size}"
            )
            assert stat.st_mtime == cls.real_db_initial_mtime, (
                f"CRITICAL REGRESSION: Real database mtime modified! Was {cls.real_db_initial_mtime}, now {stat.st_mtime}"
            )

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="soc_deploy_test_")
        self.orig_soc_data = os.environ.get("SOC_DATA_DIR")
        self.orig_soc_env = os.environ.get("SOC_ENV")
        self.orig_enable_demo = os.environ.get("SOC_ENABLE_DEMO_ACCOUNTS")
        self.orig_disable_seed = os.environ.get("SOC_DISABLE_DB_SEEDING")
        self.orig_require_db = os.environ.get("SOC_REQUIRE_EXISTING_DB")
        self.orig_db_path = db.DB_PATH

        # Explicitly disable automatic seeding from the 1.21 GB real DB in standard tests
        os.environ["SOC_DISABLE_DB_SEEDING"] = "1"

        # Direct all test database operations to an isolated temporary database
        self.isolated_db_path = Path(self.temp_dir) / "isolated_test.db"
        db.DB_PATH = self.isolated_db_path
        db.init_db()

    def tearDown(self):
        # Restore environment variables
        if self.orig_soc_data is not None:
            os.environ["SOC_DATA_DIR"] = self.orig_soc_data
        else:
            os.environ.pop("SOC_DATA_DIR", None)

        if self.orig_soc_env is not None:
            os.environ["SOC_ENV"] = self.orig_soc_env
        else:
            os.environ.pop("SOC_ENV", None)

        if self.orig_enable_demo is not None:
            os.environ["SOC_ENABLE_DEMO_ACCOUNTS"] = self.orig_enable_demo
        else:
            os.environ.pop("SOC_ENABLE_DEMO_ACCOUNTS", None)

        if self.orig_disable_seed is not None:
            os.environ["SOC_DISABLE_DB_SEEDING"] = self.orig_disable_seed
        else:
            os.environ.pop("SOC_DISABLE_DB_SEEDING", None)

        if self.orig_require_db is not None:
            os.environ["SOC_REQUIRE_EXISTING_DB"] = self.orig_require_db
        else:
            os.environ.pop("SOC_REQUIRE_EXISTING_DB", None)

        # Restore module DB_PATH
        db.DB_PATH = self.orig_db_path

        # Clean up temporary test directory
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

        # Verify real database integrity after each test
        if self.REAL_DB_PATH.exists():
            stat = self.REAL_DB_PATH.stat()
            self.assertEqual(stat.st_size, self.real_db_initial_size, "Real DB size changed during test!")
            self.assertEqual(stat.st_mtime, self.real_db_initial_mtime, "Real DB mtime changed during test!")

    def test_01_default_local_data_dir(self):
        """When SOC_DATA_DIR is unset, mutable storage defaults to PROJECT_ROOT / 'data'."""
        os.environ.pop("SOC_DATA_DIR", None)
        resolved = get_soc_data_dir()
        self.assertEqual(resolved.resolve(), (PROJECT_ROOT / "data").resolve())
        self.assertTrue(resolved.exists())

    def test_02_custom_soc_data_dir_resolution(self):
        """When SOC_DATA_DIR is set (e.g. /var/data on Render), uses that directory and creates it."""
        custom_data = Path(self.temp_dir) / "persistent_data"
        os.environ["SOC_DATA_DIR"] = str(custom_data)
        resolved = get_soc_data_dir()
        self.assertEqual(resolved.resolve(), custom_data.resolve())
        self.assertTrue(resolved.exists())

    def test_03_database_path_under_soc_data_dir_without_real_db_copy(self):
        """Database path resolves under SOC_DATA_DIR and initializes schema without touching real DB."""
        custom_data = Path(self.temp_dir) / "persistent_db_dir"
        os.environ["SOC_DATA_DIR"] = str(custom_data)
        os.environ["SOC_DISABLE_DB_SEEDING"] = "1"

        target_db = db.get_db_path()
        self.assertEqual(target_db.resolve(), (custom_data / "detection_history.db").resolve())

        # Test initializing tables in this isolated custom location
        db.DB_PATH = target_db
        db.init_db()

        conn = db.get_connection()
        self.assertIsNotNone(conn)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        table_names = [r["name"] for r in tables]
        self.assertIn("analysis_sessions", table_names)
        self.assertIn("detections", table_names)
        self.assertIn("upload_sessions", table_names)
        self.assertIn("upload_chunks", table_names)
        self.assertIn("candidate_datasets", table_names)
        self.assertIn("candidate_models", table_names)
        self.assertIn("model_activation_audit", table_names)
        conn.close()

    def test_04_target_database_never_overwritten(self):
        """seed_database_via_backup refuses to overwrite an existing database."""
        mock_src = Path(self.temp_dir) / "mock_src.db"
        mock_tgt = Path(self.temp_dir) / "mock_tgt.db"

        # Create target database with custom sentinel data
        with sqlite3.connect(str(mock_tgt)) as conn:
            conn.execute("CREATE TABLE sentinel (marker TEXT);")
            conn.execute("INSERT INTO sentinel VALUES ('DO_NOT_OVERWRITE');")
            conn.commit()

        # Create source database with different table
        with sqlite3.connect(str(mock_src)) as conn:
            conn.execute("CREATE TABLE source_data (id INT);")
            conn.execute("INSERT INTO source_data VALUES (100);")
            conn.commit()

        # Attempt seeding: must return False and refuse overwrite
        res = db.seed_database_via_backup(mock_src, mock_tgt)
        self.assertFalse(res, "Must return False when target database already exists.")

        # Verify target was NOT overwritten
        with sqlite3.connect(str(mock_tgt)) as conn:
            row = conn.execute("SELECT marker FROM sentinel;").fetchone()
            self.assertEqual(row[0], "DO_NOT_OVERWRITE")
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            self.assertNotIn("source_data", tables)

    def test_05_backup_migration_preserves_structure_and_records(self):
        """SQLite Connection.backup() safely migrates schema, tables, indexes, and row data."""
        mock_src = Path(self.temp_dir) / "source_full.db"
        mock_tgt = Path(self.temp_dir) / "target_migrated.db"

        with sqlite3.connect(str(mock_src)) as conn:
            conn.execute("CREATE TABLE analysis_sessions (session_id TEXT PRIMARY KEY, count INT, score REAL);")
            conn.execute("CREATE INDEX idx_score ON analysis_sessions (score);")
            conn.execute("INSERT INTO analysis_sessions VALUES ('SES-001', 42, 0.987);")
            conn.execute("INSERT INTO analysis_sessions VALUES ('SES-002', 10, 0.123);")
            conn.execute("CREATE TABLE detections (id TEXT PRIMARY KEY, label TEXT);")
            conn.execute("INSERT INTO detections VALUES ('DET-001', 'ATTACK_DDOS');")
            conn.commit()

        # Perform migration
        res = db.seed_database_via_backup(mock_src, mock_tgt)
        self.assertTrue(res)
        self.assertTrue(mock_tgt.exists())

        # Verify target database contents
        with sqlite3.connect(str(mock_tgt)) as conn:
            rows = conn.execute("SELECT session_id, count, score FROM analysis_sessions ORDER BY session_id;").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0], ("SES-001", 42, 0.987))
            self.assertEqual(rows[1], ("SES-002", 10, 0.123))

            det_rows = conn.execute("SELECT id, label FROM detections;").fetchall()
            self.assertEqual(det_rows[0], ("DET-001", "ATTACK_DDOS"))

            indices = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index';").fetchall()]
            self.assertIn("idx_score", indices)

    def test_06_failed_migration_leaves_no_partial_database(self):
        """If backup fails midway, no partial target database or temporary files are left behind."""
        mock_src = Path(self.temp_dir) / "source_error.db"
        mock_tgt = Path(self.temp_dir) / "target_never_created.db"
        mock_src.write_bytes(b"dummy valid bytes")

        # Simulate exception during backup via mocked connection
        mock_src_conn = MagicMock()
        mock_dst_conn = MagicMock()
        mock_src_conn.backup.side_effect = sqlite3.OperationalError("Simulated disk full")

        with patch("backend.database.sqlite3.connect", side_effect=[mock_src_conn, mock_dst_conn]):
            res = db.seed_database_via_backup(mock_src, mock_tgt)
            self.assertFalse(res)

        # Target database MUST NOT exist
        self.assertFalse(mock_tgt.exists(), "Target database must not exist after failed backup.")

        # No lingering temporary files in target directory
        tmp_files = list(Path(self.temp_dir).glob("*.tmp.*"))
        self.assertEqual(len(tmp_files), 0, "No temporary staging files should remain after failed migration.")

    def test_07_wal_mode_source_database_handled_safely(self):
        """Source database operating in WAL mode is backed up safely using read-only connection."""
        mock_src = Path(self.temp_dir) / "source_wal.db"
        mock_tgt = Path(self.temp_dir) / "target_wal_migrated.db"

        # Initialize WAL mode and write records
        with sqlite3.connect(str(mock_src)) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("CREATE TABLE wal_test (id INT PRIMARY KEY, note TEXT);")
            conn.execute("INSERT INTO wal_test VALUES (1, 'base_page');")
            conn.commit()
            # Insert into active WAL without checkpoint
            conn.execute("INSERT INTO wal_test VALUES (2, 'wal_page');")
            conn.commit()

        # Verify WAL journal exists
        wal_file = Path(self.temp_dir) / "source_wal.db-wal"
        self.assertTrue(wal_file.exists(), "WAL file should exist for WAL-mode test source.")

        # Migrate via read-only backup
        res = db.seed_database_via_backup(mock_src, mock_tgt)
        self.assertTrue(res)

        # Verify target contains both the base page and WAL page records
        with sqlite3.connect(str(mock_tgt)) as conn:
            rows = conn.execute("SELECT id, note FROM wal_test ORDER BY id;").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0], (1, "base_page"))
            self.assertEqual(rows[1], (2, "wal_page"))

    def test_08_temporary_tests_do_not_access_original_detection_database(self):
        """Temporary tests writing sessions, detections, or tokens never modify real DB."""
        initial_stat = self.REAL_DB_PATH.stat()

        # Execute operations against the isolated database
        db.save_user_session({
            "token": "TEST-TOKEN-ISOLATED",
            "email": "test@soc.ai",
            "created_at": "2026-11-25 21:00:00",
            "expires_at": "2026-11-25 22:00:00"
        })
        db.insert_session({
            "session_id": "TEST-SES-001",
            "source_name": "Test",
            "input_type": "profile",
            "timestamp": "2026-11-25 21:00:00",
            "total_records": 1,
            "normal_events": 1,
            "threats_detected": 0,
            "invalid_records": 0,
            "threat_ratio": 0.0,
            "attack_categories": {},
            "severity_distribution": {},
            "model_summary": {}
        })

        # Verify operations were captured in isolated test DB
        with sqlite3.connect(str(self.isolated_db_path)) as conn:
            sess = conn.execute("SELECT session_id FROM analysis_sessions WHERE session_id='TEST-SES-001';").fetchone()
            self.assertIsNotNone(sess)

        # Assert real database was never touched
        current_stat = self.REAL_DB_PATH.stat()
        self.assertEqual(current_stat.st_size, initial_stat.st_size)
        self.assertEqual(current_stat.st_mtime, initial_stat.st_mtime)

    def test_09_password_reset_uses_isolated_db_and_never_logs_token(self):
        """Password recovery audit logging never logs token (not even masked/prefix) and writes only to isolated DB."""
        clean_email = "analyst@soc.ai"
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            res = auth.request_password_recovery(clean_email)

        log_output = captured.getvalue()
        self.assertIn("[AUTH_AUDIT]", log_output)
        self.assertIn(clean_email, log_output)
        self.assertIn("expires:", log_output)

        # Retrieve the generated token from the isolated test database
        with sqlite3.connect(str(self.isolated_db_path)) as conn:
            row = conn.execute("SELECT token, email, used FROM password_recovery_requests WHERE email=?;", (clean_email,)).fetchone()
            self.assertIsNotNone(row, "Recovery token must be stored in the isolated test database.")
            raw_token = row[0]
            self.assertEqual(row[1], clean_email)

        # Full token, prefix (first 8 chars), suffix (last 8 chars), and masked stars must NEVER appear in stdout audit logs
        self.assertNotIn(raw_token, log_output)
        self.assertNotIn(raw_token[:8], log_output)
        self.assertNotIn(raw_token[-8:], log_output)
        self.assertNotIn("***", log_output)

    def test_10_uploads_root_under_soc_data_dir(self):
        """Uploads root and per-upload staging directories resolve under SOC_DATA_DIR."""
        custom_data = Path(self.temp_dir) / "persistent_uploads"
        os.environ["SOC_DATA_DIR"] = str(custom_data)

        uploads_root = uploader.get_uploads_root()
        self.assertEqual(uploads_root.resolve(), (custom_data / "uploads").resolve())
        self.assertTrue(uploads_root.exists())

        upload_id = "UPL-TEST-SESSION-001"
        staging_dir = uploader.get_upload_dir(upload_id)
        self.assertEqual(staging_dir.resolve(), (custom_data / "uploads" / upload_id).resolve())
        self.assertTrue(staging_dir.exists())

    def test_11_candidate_datasets_under_soc_data_dir(self):
        """Candidate datasets and models resolve to SOC_DATA_DIR when configured."""
        custom_data = Path(self.temp_dir) / "persistent_candidates"
        os.environ["SOC_DATA_DIR"] = str(custom_data)

        ds_dir = tm.get_candidate_datasets_dir()
        self.assertEqual(ds_dir.resolve(), (custom_data / "candidate_datasets").resolve())
        self.assertTrue(ds_dir.exists())

        cand_models_dir = tm.get_candidate_models_dir()
        self.assertEqual(cand_models_dir.resolve(), (custom_data / "models" / "candidates").resolve())
        self.assertTrue(cand_models_dir.exists())

        backups_dir = tm.get_model_backups_dir()
        self.assertEqual(backups_dir.resolve(), (custom_data / "models" / "backups").resolve())
        self.assertTrue(backups_dir.exists())

    def test_12_immutable_model_artifacts_preserved(self):
        """Experiment B trained models and baseline metrics remain intact under PROJECT_ROOT."""
        models_dir = PROJECT_ROOT / "models" / "saved_exp_b"
        self.assertTrue((models_dir / "fcnn_model.keras").exists(), "fcnn_model.keras must exist")
        self.assertTrue((models_dir / "cnn_model.keras").exists(), "cnn_model.keras must exist")
        self.assertTrue((models_dir / "lstm_model.keras").exists(), "lstm_model.keras must exist")
        self.assertTrue((models_dir / "isolation_forest.joblib").exists(), "isolation_forest.joblib must exist")
        self.assertTrue((models_dir / "ensemble_config.json").exists(), "ensemble_config.json must exist")

        drift_ref = PROJECT_ROOT / "data" / "reference_baselines" / "drift_reference_exp_b.json"
        self.assertTrue(drift_ref.exists(), "drift_reference_exp_b.json must exist")

    def test_13_auth_demo_accounts_disabled_in_production(self):
        """When SOC_ENV=production and SOC_ENABLE_DEMO_ACCOUNTS=false, demo operator logins are denied."""
        with patch.object(auth, "IS_PRODUCTION", True), \
             patch.object(auth, "ENABLE_DEMO_ACCOUNTS", False):
            with self.assertRaises(ValueError) as cm:
                auth.authenticate_operator("admin@soc.ai", "CyberShield2026!")
            self.assertIn("Demo operator accounts are disabled in production", str(cm.exception))

    def test_14_fastapi_startup_event_initialization(self):
        """Startup event successfully initializes DB, upload directories, and candidate directories."""
        custom_data = Path(self.temp_dir) / "persistent_startup"
        os.environ["SOC_DATA_DIR"] = str(custom_data)
        os.environ["SOC_DISABLE_DB_SEEDING"] = "1"
        db.DB_PATH = custom_data / "detection_history.db"

        with TestClient(app) as client:
            resp = client.get("/api/status")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data.get("status"), "OPERATIONAL")

        self.assertTrue((custom_data / "uploads").exists())
        self.assertTrue((custom_data / "candidate_datasets").exists())
        self.assertTrue((custom_data / "detection_history.db").exists())

    def test_15_inference_pipeline_preserved(self):
        """Single event profile inference produces valid predictions and writes to isolated DB."""
        vector = [0.1, 0.05, 0.08, 0.02, 0.12, 0.03, 0.06, 0.04]
        res = siem_service.predict_single_profile(vector)
        self.assertIn("verdict", res)
        self.assertIn("confidence", res)
        self.assertIn("threat_confidence", res)
        self.assertIn("model_breakdown", res)
        self.assertIn("anomaly", res)
        self.assertIn(res["verdict"], ["NORMAL", "ATTACK", "SUSPICIOUS_ANOMALY"])

        # Verify the detection was written to isolated test DB
        with sqlite3.connect(str(self.isolated_db_path)) as conn:
            cnt = conn.execute("SELECT count(*) FROM detections;").fetchone()[0]
            self.assertGreaterEqual(cnt, 1, "Detection must be logged to the isolated test database.")

    def test_16_hardlink_creation_succeeds(self):
        """Hard-link installation creates target pointing to staging data and removes staging name."""
        staging = Path(self.temp_dir) / "staging_16.db"
        target = Path(self.temp_dir) / "target_16.db"
        staging.write_bytes(b"test_sqlite_payload_data")

        res = db.install_database_via_hardlink(staging, target)
        self.assertTrue(res)
        self.assertTrue(target.exists())
        self.assertFalse(staging.exists())
        self.assertEqual(target.read_bytes(), b"test_sqlite_payload_data")

    def test_17_hardlink_installation_refuses_to_overwrite_existing_target(self):
        """Hard-link installation aborts with FileExistsError and preserves target if target exists."""
        staging = Path(self.temp_dir) / "staging_17.db"
        target = Path(self.temp_dir) / "target_17.db"
        staging.write_bytes(b"new_staged_content")
        target.write_bytes(b"existing_protected_content")

        with self.assertRaises(FileExistsError):
            db.install_database_via_hardlink(staging, target)

        # Target must remain completely unmodified
        self.assertEqual(target.read_bytes(), b"existing_protected_content")
        # Staging must be preserved
        self.assertTrue(staging.exists())
        self.assertEqual(staging.read_bytes(), b"new_staged_content")

    def test_18_hardlink_installation_preserves_staging_on_failure(self):
        """If os.link fails during installation, staging database is preserved intact."""
        staging = Path(self.temp_dir) / "staging_18.db"
        target = Path(self.temp_dir) / "target_18.db"
        staging.write_bytes(b"important_staging_bytes")

        orig_link = os.link
        target_resolved = target.resolve()
        def mock_link_fail(src, dst):
            if Path(dst).resolve() == target_resolved:
                raise OSError("Simulated I/O link error")
            return orig_link(src, dst)

        with patch("backend.database.os.link", side_effect=mock_link_fail):
            with self.assertRaises(RuntimeError) as cm:
                db.install_database_via_hardlink(staging, target)
            self.assertIn("Hard-link installation failed", str(cm.exception))

        # Staging must be preserved
        self.assertTrue(staging.exists())
        self.assertEqual(staging.read_bytes(), b"important_staging_bytes")
        self.assertFalse(target.exists())

    def test_19_unsupported_hardlinks_causes_safe_failure_without_fallback(self):
        """If target filesystem does not support hard links, installation aborts without fallback."""
        staging = Path(self.temp_dir) / "staging_19.db"
        target = Path(self.temp_dir) / "target_19.db"
        staging.write_bytes(b"staging_19_content")

        with patch("backend.database.os.link", side_effect=OSError(1, "Operation not permitted")):
            with self.assertRaises(RuntimeError) as cm:
                db.install_database_via_hardlink(staging, target)
            self.assertIn("does not support hard links", str(cm.exception))

        self.assertTrue(staging.exists())
        self.assertFalse(target.exists())

    def test_20_strict_mode_refuses_missing_database_without_creating_it(self):
        """Strict mode refuses missing DB, raising RuntimeError and NOT creating a 0-byte file."""
        missing_path = Path(self.temp_dir) / "strict_missing.db"
        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.DB_PATH = missing_path

        with self.assertRaises(RuntimeError) as cm:
            db.get_connection()
        self.assertIn("does not exist", str(cm.exception))

        with self.assertRaises(RuntimeError) as cm2:
            db.init_db()
        self.assertIn("does not exist", str(cm2.exception))

        # CRITICAL: Verify SQLite did NOT create an empty file
        self.assertFalse(missing_path.exists(), "Strict mode must abort before SQLite creates a 0-byte file!")

    def test_21_strict_mode_refuses_empty_database(self):
        """Strict mode refuses an empty (0 bytes) database file."""
        empty_path = Path(self.temp_dir) / "strict_empty.db"
        empty_path.write_bytes(b"")
        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.DB_PATH = empty_path

        with self.assertRaises(RuntimeError) as cm:
            db.init_db()
        self.assertIn("empty (0 bytes)", str(cm.exception))

    def test_22_strict_mode_refuses_corrupted_database(self):
        """Strict mode refuses invalid or corrupted non-SQLite database bytes."""
        corrupt_path = Path(self.temp_dir) / "strict_corrupt.db"
        corrupt_path.write_bytes(b"RANDOM_CORRUPT_BYTES_NOT_SQLITE")
        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.DB_PATH = corrupt_path

        with self.assertRaises(RuntimeError) as cm:
            db.init_db()
        self.assertTrue("corrupted" in str(cm.exception) or "Could not open" in str(cm.exception))

    def test_23_strict_mode_refuses_missing_required_tables(self):
        """Strict mode refuses a database missing required tables."""
        incomplete_path = Path(self.temp_dir) / "strict_missing_tables.db"
        with sqlite3.connect(str(incomplete_path)) as conn:
            conn.execute("CREATE TABLE partial_table (id INT PRIMARY KEY);")
            conn.commit()

        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.DB_PATH = incomplete_path

        with self.assertRaises(RuntimeError) as cm:
            db.init_db()
        self.assertIn("missing required tables", str(cm.exception))

    def test_24_strict_mode_refuses_missing_required_columns(self):
        """Strict mode refuses a database missing required table columns."""
        incomplete_path = Path(self.temp_dir) / "strict_missing_columns.db"
        with sqlite3.connect(str(incomplete_path)) as conn:
            for t in db.REQUIRED_DATABASE_TABLES:
                conn.execute(f"CREATE TABLE {t} (dummy_col TEXT);")
            conn.commit()

        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.DB_PATH = incomplete_path

        with self.assertRaises(RuntimeError) as cm:
            db.init_db()
        self.assertIn("missing required columns", str(cm.exception))

    def test_25_valid_database_passes_startup_validation(self):
        """Valid database with all tables and columns passes validation regardless of row count."""
        valid_path = Path(self.temp_dir) / "strict_valid.db"
        os.environ.pop("SOC_REQUIRE_EXISTING_DB", None)
        db.DB_PATH = valid_path
        db.init_db()

        # In strict mode, startup validation passes smoothly
        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.init_db()
        conn = db.get_connection()
        self.assertIsNotNone(conn)
        conn.close()

    def test_26_local_dev_still_creates_fresh_database_when_not_strict(self):
        """When SOC_REQUIRE_EXISTING_DB is disabled, local dev creates fresh database normally."""
        os.environ.pop("SOC_REQUIRE_EXISTING_DB", None)
        fresh_path = Path(self.temp_dir) / "fresh_dev_local.db"
        self.assertFalse(fresh_path.exists())

        db.DB_PATH = fresh_path
        db.init_db()

        self.assertTrue(fresh_path.exists())
        with sqlite3.connect(str(fresh_path)) as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            self.assertIn("analysis_sessions", tables)
            self.assertIn("detections", tables)

    def test_27_existing_database_initialization_and_schema_migrations_still_work(self):
        """Existing older database missing newer columns successfully migrates in strict mode and passes validation."""
        old_db_path = Path(self.temp_dir) / "legacy_schema.db"
        with sqlite3.connect(str(old_db_path)) as conn:
            conn.execute("""
            CREATE TABLE analysis_sessions (
                session_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_name TEXT NOT NULL,
                input_type TEXT NOT NULL,
                total_records INTEGER NOT NULL,
                normal_events INTEGER NOT NULL,
                threats_detected INTEGER NOT NULL,
                known_threats INTEGER NOT NULL DEFAULT 0,
                unknown_anomalous INTEGER NOT NULL DEFAULT 0,
                invalid_records INTEGER NOT NULL,
                threat_ratio REAL NOT NULL,
                attack_categories TEXT NOT NULL,
                severity_distribution TEXT NOT NULL,
                model_summary TEXT NOT NULL
            );
            """)
            conn.execute("""
            CREATE TABLE detections (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                input_type TEXT NOT NULL,
                verdict TEXT NOT NULL,
                threat_confidence REAL NOT NULL,
                severity TEXT NOT NULL
            );
            """)
            conn.commit()

        # In strict mode, init_db() must run ALTER TABLE migrations before validation, allowing it to succeed
        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.DB_PATH = old_db_path
        db.init_db()

        with sqlite3.connect(str(old_db_path)) as conn:
            cols = [c[1] for c in conn.execute("PRAGMA table_info(analysis_sessions);").fetchall()]
            self.assertIn("report_data", cols, "Migration must have added report_data column to analysis_sessions.")

    def test_28_get_connection_and_validation_use_same_resolved_path(self):
        """get_connection() and validate_production_database() resolve to the identical path."""
        custom_data = Path(self.temp_dir) / "canonical_resolve"
        os.environ["SOC_DATA_DIR"] = str(custom_data)
        db.DB_PATH = PROJECT_ROOT / "data" / "detection_history.db"

        resolved = db.get_resolved_db_path()
        expected = (custom_data / "detection_history.db").resolve()
        self.assertEqual(resolved, expected)

        os.environ.pop("SOC_REQUIRE_EXISTING_DB", None)
        db.init_db()

        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.validate_production_database()
        conn = db.get_connection()
        self.assertIsNotNone(conn)
        conn.close()

    def test_29_strict_mode_race_condition_never_creates_empty_file(self):
        """Strict mode get_connection() uses mode=rw and refuses to create a 0-byte file if file is removed."""
        race_path = Path(self.temp_dir) / "race_test.db"
        race_path.write_bytes(b"initial_bytes")
        os.environ["SOC_REQUIRE_EXISTING_DB"] = "true"
        db.DB_PATH = race_path

        # Unlink the file immediately before get_connection to simulate a race condition
        race_path.unlink()

        with self.assertRaises(RuntimeError) as cm:
            db.get_connection()
        self.assertTrue("does not exist" in str(cm.exception) or "mode=rw" in str(cm.exception))
        self.assertFalse(race_path.exists(), "Strict mode must never create an empty file under race conditions!")

    def test_30_maintenance_server_head_and_get_routes(self):
        """Maintenance server returns 200 on health routes for both GET and HEAD, and 503 for all others."""
        import http.client
        import http.server
        import threading
        from scripts.maintenance_server import MaintenanceHTTPHandler, HEALTH_PATHS

        server = http.server.HTTPServer(("127.0.0.1", 0), MaintenanceHTTPHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

            # Test all configured health check paths
            for path in HEALTH_PATHS:
                # GET -> 200 OK
                conn.request("GET", path)
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.getheader("Content-Type"), "application/json")
                self.assertIn(b'"HEALTHY"', body)

                # HEAD -> 200 OK, no body
                conn.request("HEAD", path)
                resp = conn.getresponse()
                head_body = resp.read()
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.getheader("Content-Type"), "application/json")
                self.assertEqual(len(head_body), 0)

            # Test arbitrary and API paths -> 503 Maintenance
            for path in ("/", "/api/status", "/index.html", "/data/detection_history.db"):
                # GET -> 503 Service Unavailable
                conn.request("GET", path)
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(resp.getheader("Content-Type"), "application/json")
                self.assertEqual(resp.getheader("Retry-After"), "300")
                self.assertIn(b'"MAINTENANCE"', body)
                # Verify no file contents or directory listings leaked
                self.assertNotIn(b"SQLite format", body)
                self.assertNotIn(b"<!DOCTYPE", body)

                # HEAD -> 503 Service Unavailable, no body
                conn.request("HEAD", path)
                resp = conn.getresponse()
                head_body = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(resp.getheader("Content-Type"), "application/json")
                self.assertEqual(resp.getheader("Retry-After"), "300")
                self.assertEqual(len(head_body), 0)

            conn.close()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
