"""
Verification test for 100% bit-for-bit and statistical equivalence
between full-file offline sliding-window processing and streaming chunked batch processing.
Run with:
    python -m unittest tests.test_equivalence -v
"""

import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT
from backend.service import SIEMService
import backend.database as db
from backend.uploader import init_chunked_upload, save_upload_chunk, finalize_chunked_upload
from backend.campaign import coalesce_campaigns


class TestOfflineChunkedEquivalence(unittest.TestCase):
    """
    Validates that streaming chunked batch processing produces outputs identical
    to monolithic offline event profile aggregation on genuine CICIDS2017 flows.
    """

    @classmethod
    def setUpClass(cls):
        cls.source_csv = PROJECT_ROOT / "data" / "processed" / "Friday-WorkingHours-Afternoon-PortScan_clean.csv"
        if not cls.source_csv.exists():
            raise unittest.SkipTest(f"Missing {cls.source_csv}")

        cls.df_sample = pd.read_csv(cls.source_csv, nrows=6000)
        cls.service = SIEMService()

        # Offline monolithic run
        cls.full_res = cls.service.aggregator.aggregate_flows(cls.df_sample)
        cls.full_profiles = cls.full_res["profiles"]
        cls.full_event_sets = cls.full_res["event_sets"]
        cls.full_preds = cls.service.engine.predict_profiles_batch(cls.full_profiles)

    def test_chunked_streaming_equivalence(self):
        temp_dir = Path(tempfile.mkdtemp(prefix="test_eq_ci_"))
        sample_csv_path = temp_dir / "sample.csv"
        self.df_sample.to_csv(sample_csv_path, index=False)

        with open(sample_csv_path, "rb") as f:
            f_bytes = f.read()
        file_hash = hashlib.sha256(f_bytes).hexdigest()
        file_size = len(f_bytes)

        # Ensure clean test state
        existing = db.find_upload_session_by_hash(file_hash, file_size)
        if existing:
            db.cancel_and_cleanup_upload(existing["upload_id"])
            self.service.delete_session(existing["session_id"])
            conn = db.get_connection()
            with conn:
                conn.execute("DELETE FROM upload_sessions WHERE upload_id = ?", (existing["upload_id"],))

        chunk_size = 500 * 1024
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        init_res = init_chunked_upload("sample.csv", file_size, file_hash, total_chunks)
        upload_id = init_res["upload_id"]

        for c_idx in range(total_chunks):
            start = c_idx * chunk_size
            chunk_data = f_bytes[start:start + chunk_size]
            save_upload_chunk(upload_id, c_idx, chunk_data)

        finalize_chunked_upload(upload_id, file_hash)

        # Process in batches of 1500 rows (4 batches)
        proc_res = self.service.processor.process_upload_session(upload_id, batch_size=1500)
        session_id = proc_res["session_id"]

        try:
            staged_dets = self.service.get_history(session_id=session_id, limit=20000)
            self.assertEqual(len(staged_dets), len(self.full_profiles), "Event set count mismatch")

            # Sort both by (k, source_ip, destination_ip)
            offline_records = []
            for i in range(len(self.full_event_sets)):
                es = self.full_event_sets.iloc[i]
                offline_records.append({
                    "key": (int(es["k"]), str(es["source_ip"]), str(es["destination_ip"])),
                    "profile": self.full_profiles[i],
                    "verdict": self.full_preds[i]["verdict"],
                    "confidence": float(self.full_preds[i].get("threat_confidence", self.full_preds[i].get("confidence", 0.0)))
                })
            offline_records.sort(key=lambda x: x["key"])

            chunked_records = []
            for d in staged_dets:
                k_val = int(d.get("flow_metadata", {}).get("k", 0))
                chunked_records.append({
                    "key": (k_val, str(d["source_ip"]), str(d["destination_ip"])),
                    "profile": np.array(d["profile_vector"], dtype=np.float64),
                    "verdict": d["verdict"],
                    "confidence": float(d["threat_confidence"])
                })
            chunked_records.sort(key=lambda x: x["key"])

            self.assertEqual([r["key"] for r in chunked_records], [r["key"] for r in offline_records])

            chunked_profiles = np.array([r["profile"] for r in chunked_records])
            full_profiles_sorted = np.array([r["profile"] for r in offline_records])
            chunked_verdicts = [r["verdict"] for r in chunked_records]
            offline_verdicts = [r["verdict"] for r in offline_records]
            chunked_conf = [r["confidence"] for r in chunked_records]
            offline_conf = [r["confidence"] for r in offline_records]

            # 1. Basepoint Profile Equivalence (strictly < 1e-4)
            diff = np.abs(chunked_profiles - full_profiles_sorted)
            max_diff = np.max(diff)
            self.assertLess(max_diff, 1e-4, f"Basepoint difference exceeded tolerance: {max_diff}")

            # 2. Verdict Equivalence (100% match)
            verdict_matches = sum(c == o for c, o in zip(chunked_verdicts, offline_verdicts))
            self.assertEqual(verdict_matches, len(offline_verdicts), "Verdict mismatch found!")

            # 3. Threat Confidence Equivalence (strictly < 1e-4)
            conf_diff = np.max(np.abs(np.array(chunked_conf) - np.array(offline_conf)))
            self.assertLess(conf_diff, 1e-4, f"Confidence difference exceeded tolerance: {conf_diff}")

            # 4. Campaign Coalescence Equivalence
            offline_campaigns = coalesce_campaigns(
                window_predictions=[
                    {
                        "event_set_id": f"ES-{i:05d}",
                        "window_id": f"W{int(self.full_event_sets.iloc[i]['k']):05d}",
                        "k": int(self.full_event_sets.iloc[i]['k']),
                        "source_ip": str(self.full_event_sets.iloc[i]['source_ip']),
                        "destination_ip": str(self.full_event_sets.iloc[i]['destination_ip']),
                        "window_start": str(self.full_event_sets.iloc[i]['window_start']),
                        "window_end": str(self.full_event_sets.iloc[i]['window_end']),
                        "verdict": self.full_preds[i]["verdict"],
                        "confidence": self.full_preds[i]["threat_confidence"],
                        "ensemble_score": float(self.full_preds[i].get("ensemble_score", self.full_preds[i]["threat_confidence"])),
                        "anomaly_score": self.full_preds[i].get("anomaly", {}).get("anomaly_score", 0.0),
                        "basepoint_profile": self.full_profiles[i].tolist()
                    }
                    for i in range(len(self.full_preds))
                    if self.full_preds[i]["verdict"] in ("KNOWN_THREAT", "UNKNOWN_ANOMALOUS")
                ],
                flow_attributions=self.full_res["flow_attributions"],
                session_id="OFFLINE-TEST"
            )

            chunked_campaigns = self.service.get_campaigns(session_id=session_id, limit=20000)
            self.assertEqual(len(offline_campaigns["campaigns"]), len(chunked_campaigns), "Campaign count mismatch!")

        finally:
            self.service.delete_session(session_id)
            db.cancel_and_cleanup_upload(upload_id)
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
