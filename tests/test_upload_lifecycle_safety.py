"""
Unit and integration tests for upload lifecycle safety, deletion coordination,
and resilience against file deletion during streaming batch inference.
Run with:
    python -m unittest tests.test_upload_lifecycle_safety -v
"""

import hashlib
import io
import tempfile
import unittest
import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from src.config import PROJECT_ROOT
from backend.main import app
from backend.service import siem_service
import backend.database as db
import backend.uploader as uploader


class TestUploadLifecycleSafety(unittest.TestCase):
    """
    Tests backend cancellation rejection during active processing,
    missing-source resume guards, idempotent finalization, and protected incident safety.
    """

    def setUp(self):
        self.client = TestClient(app)
        self.test_uids = []
        self.test_sids = []

    def tearDown(self):
        for uid in self.test_uids:
            try:
                uploader.cleanup_upload(uid)
            except Exception:
                pass
        for sid in self.test_sids:
            try:
                db.delete_session(sid)
            except Exception:
                pass

    def test_protected_incident_records_are_preserved(self):
        """
        PRIORITY 4: Verify that incident UPL-20261118220457-b41aa8a7 staging records
        and checkpoints are untouched and cannot be purged.
        """
        incident_uid = "UPL-20261118220457-b41aa8a7"
        
        # 1. Attempting cleanup must be explicitly rejected
        with self.assertRaises(ValueError):
            uploader.cleanup_upload(incident_uid)

        # 2. DELETE endpoint must return HTTP 403 Forbidden
        resp = self.client.delete(f"/api/upload/{incident_uid}")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("protected", resp.text.lower())

        # 3. Verify staging records remain preserved in SQLite
        chk_count = len(db.get_all_checkpoints(incident_uid))
        self.assertGreaterEqual(chk_count, 1)

        int_dets = db.get_intermediate_detections(incident_uid)
        self.assertGreaterEqual(len(int_dets), 30000)

        pending_wins = db.get_pending_alert_windows(incident_uid)
        self.assertGreaterEqual(len(pending_wins), 800)

    def test_delete_rejected_during_active_processing(self):
        """
        PRIORITY 2: Verify that DELETE /api/upload/{upload_id} returns HTTP 409 Conflict
        when an upload is actively being processed by a worker thread.
        """
        uid = f"UPL-TEST-{int(time.time())}-active"
        sid = f"SESS-TEST-{int(time.time())}-active"
        self.test_uids.append(uid)
        self.test_sids.append(sid)

        # Create session in PROCESSING state
        db.create_upload_session(
            upload_id=uid,
            session_id=sid,
            filename="active_test.csv",
            file_size=10000,
            file_hash="a" * 64,
            total_chunks=1
        )
        db.update_upload_status(uid, processing_status="PROCESSING")

        # Simulate active worker thread registered in service
        dummy_thread = threading.Thread(target=lambda: time.sleep(1))
        dummy_thread.start()
        siem_service.register_worker(uid, dummy_thread)

        try:
            # DELETE must be rejected with 409 Conflict
            resp = self.client.delete(f"/api/upload/{uid}")
            self.assertEqual(resp.status_code, 409)
            self.assertIn("actively in progress", resp.text)
        finally:
            siem_service.unregister_worker(uid)
            dummy_thread.join()

    def test_delete_permitted_when_inactive(self):
        """
        PRIORITY 2: Verify that DELETE /api/upload/{upload_id} succeeds
        when the upload is PAUSED, FAILED, or CANCELLED.
        """
        uid = f"UPL-TEST-{int(time.time())}-inactive"
        sid = f"SESS-TEST-{int(time.time())}-inactive"
        self.test_sids.append(sid)

        db.create_upload_session(
            upload_id=uid,
            session_id=sid,
            filename="inactive_test.csv",
            file_size=10000,
            file_hash="b" * 64,
            total_chunks=1
        )
        db.update_upload_status(uid, processing_status="PAUSED")

        # Create a mock upload directory
        up_dir = PROJECT_ROOT / "data" / "uploads" / uid
        up_dir.mkdir(parents=True, exist_ok=True)
        (up_dir / "sample.txt").write_text("test")

        resp = self.client.delete(f"/api/upload/{uid}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["cancelled"])
        self.assertFalse(up_dir.exists(), "Upload directory must be removed when safely inactive")

    def test_missing_source_file_prevents_unsafe_resume(self):
        """
        PRIORITY 3: Verify that resuming an upload session whose on-disk source files
        have been deleted returns HTTP 410 Gone instead of crashing.
        """
        uid = f"UPL-TEST-{int(time.time())}-missing"
        sid = f"SESS-TEST-{int(time.time())}-missing"
        self.test_uids.append(uid)
        self.test_sids.append(sid)

        db.create_upload_session(
            upload_id=uid,
            session_id=sid,
            filename="missing_test.csv",
            file_size=10000,
            file_hash="c" * 64,
            total_chunks=1
        )
        db.update_upload_status(uid, processing_status="PAUSED")

        # Resume request when on-disk directory does NOT exist
        resume_payload = {
            "upload_id": uid,
            "file_hash": "c" * 64,
            "sync": True
        }
        resp = self.client.post("/api/process/resume", json=resume_payload)
        self.assertEqual(resp.status_code, 410)
        self.assertIn("missing on disk", resp.text.lower())

    def test_idempotent_finalization(self):
        """
        PRIORITY 3: Calling /api/upload/finalize multiple times must be idempotent
        and not re-read or corrupt state.
        """
        sample_data = b"timestamp,source_ip,destination_ip,flow_duration,flow_packets_s,flow_bytes_s,syn_flag_count\n"
        file_hash = hashlib.sha256(sample_data).hexdigest()
        file_size = len(sample_data)

        init_res = uploader.init_chunked_upload("idem_test.csv", file_size, file_hash, 1)
        uid = init_res["upload_id"]
        sid = init_res["session_id"]
        self.test_uids.append(uid)
        self.test_sids.append(sid)

        uploader.save_upload_chunk(uid, 0, sample_data)

        # 1st finalization
        fin1 = self.client.post("/api/upload/finalize", json={"upload_id": uid, "file_hash": file_hash})
        self.assertEqual(fin1.status_code, 200)

        # 2nd finalization (must succeed idempotently)
        fin2 = self.client.post("/api/upload/finalize", json={"upload_id": uid, "file_hash": file_hash})
        self.assertEqual(fin2.status_code, 200)
        self.assertEqual(fin2.json()["status"], "UPLOAD_COMPLETE")


if __name__ == "__main__":
    unittest.main()
