"""
Unit tests for Stage 4: Checkpoint-Based Batch Processing & Resumption.
Simulates interruption midway (2 of 4 batches), server crash and restart,
and resumption to complete the full session without reprocessing or duplication.
Run with:
    python -m unittest tests.test_batch_processing_resumption -v
"""

import hashlib
import os
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT
from backend.service import SIEMService
import backend.uploader as uploader
import backend.database as db


class TestBatchProcessingResumption(unittest.TestCase):
    """
    Tests pausing, crash recovery, and idempotent resumption of chunked streaming ingestion.
    """

    def setUp(self):
        proc_dir = PROJECT_ROOT / "data" / "processed"
        self.source_csv = proc_dir / "Friday-WorkingHours-Afternoon-PortScan_clean.csv"
        if not self.source_csv.exists():
            raise unittest.SkipTest(f"Missing {self.source_csv}")

        df_raw = pd.read_csv(self.source_csv, nrows=4000)
        cols = ["timestamp", "source_ip", "destination_ip", "flow_duration", "flow_packets_s", "flow_bytes_s", "syn_flag_count"]
        df_sample = df_raw[cols].copy()

        # Scramble rows to test out-of-order handling
        rng = np.random.default_rng(123)
        perm = rng.permutation(len(df_sample))
        self.df_scrambled = df_sample.iloc[perm].reset_index(drop=True)

        self.csv_bytes = self.df_scrambled.to_csv(index=False).encode("utf-8")
        self.full_sha256 = hashlib.sha256(self.csv_bytes).hexdigest()
        self.file_size = len(self.csv_bytes)
        self.chunk_size = 50000
        self.chunks = [self.csv_bytes[i:i+self.chunk_size] for i in range(0, self.file_size, self.chunk_size)]
        self.total_chunks = len(self.chunks)

        # Clean prior state
        existing = db.find_upload_session_by_hash(self.full_sha256, self.file_size)
        if existing:
            uploader.cleanup_upload(existing["upload_id"])
            db.delete_session(existing["session_id"])

    def test_interruption_and_resumption(self):
        # 1. Upload file in chunks
        init_res = uploader.init_chunked_upload("portscan_scrambled_test.csv", self.file_size, self.full_sha256, self.total_chunks)
        uid = init_res["upload_id"]
        sid = init_res["session_id"]

        try:
            for i, c in enumerate(self.chunks):
                uploader.save_upload_chunk(uid, i, c)
            uploader.finalize_chunked_upload(uid, self.full_sha256)

            # 2. Service 1 runs first 2 batches of 1,000 rows (simulating 50% interruption)
            service1 = SIEMService(experiment_id="B")
            self.assertIsNone(db.get_session_by_id(sid))

            batch_size = 1000
            res_part1 = service1.start_stream_processing(upload_id=uid, batch_size=batch_size, max_batches=2)
            self.assertEqual(res_part1["status"], "PAUSED")
            self.assertEqual(res_part1["completed_batches"], 2)

            chk_list = db.get_all_checkpoints(uid)
            self.assertEqual(len(chk_list), 2)
            self.assertEqual(chk_list[0]["batch_index"], 0)
            self.assertEqual(chk_list[1]["batch_index"], 1)

            # No master session leakage mid-processing
            self.assertIsNone(db.get_session_by_id(sid))

            # 3. Simulate crash and restart
            del service1
            service2 = SIEMService(experiment_id="B")

            status2 = service2.get_stream_processing_status(uid)
            self.assertEqual(status2["completed_batches"], 2)

            # 4. Resume processing
            res_final = service2.start_stream_processing(upload_id=uid, batch_size=batch_size)
            self.assertEqual(res_final["status"], "COMPLETED")

            sess_summary = res_final["summary"]
            self.assertEqual(sess_summary["session_id"], sid)
            self.assertEqual(sess_summary["total_records"], 4000)

            # Verify master session created
            db_sess = db.get_session_by_id(sid)
            self.assertIsNotNone(db_sess)
            self.assertEqual(db_sess["total_records"], 4000)

            # Verify production detections and campaigns persisted
            dets = db.get_detections(limit=100, session_id=sid)
            self.assertGreater(len(dets), 0)

            camps = db.get_campaigns(limit=50, session_id=sid)
            self.assertGreater(len(camps), 0)

            # Verify staging tables cleaned up
            int_dets = db.get_intermediate_detections(uid)
            self.assertEqual(len(int_dets), 0)
            pending_wins = db.get_pending_alert_windows(uid)
            self.assertEqual(len(pending_wins), 0)

        finally:
            uploader.cleanup_upload(uid)
            db.delete_session(sid)


if __name__ == "__main__":
    unittest.main()
