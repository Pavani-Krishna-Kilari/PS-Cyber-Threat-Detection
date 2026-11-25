"""
Streaming Batch Processing Engine with Checkpoint-Based Resumability for AI-SIEM.
Processes large network flow CSVs incrementally in bounded-RAM batches, preserving
exact sliding-window semantics (W=600s, S=60s) across batch boundaries.
"""

import gc
import json
import math
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT
import backend.database as db
from backend.uploader import get_upload_dir
from backend.parser import normalize_and_deduplicate_dataframe, clean_column_name, PROFILE_COLS
from backend.sorter import external_sort_csv
from backend.campaign import coalesce_campaigns
from backend.aggregator import (
    RawFlowAggregator,
    InsufficientTemporalSpanError,
    AggregatorError,
    MissingFeatureColumnsError,
    InvalidTimestampError
)
from src.event_profiles.windows import compute_bins, valid_windows, aggregate_to_windows
from src.event_profiles.events import apply_flow_events, compare, EVENT_NAMES, FLOW_EVENT_SPECS
from src.event_profiles.tfidf import transform
from src.event_profiles.basepoints import compute_profiles


class StreamBatchProcessor:
    """
    Manages streaming batch inference and checkpoint-based recovery for an uploaded file.
    """

    def __init__(self, service_instance, default_batch_size: int = 20000):
        self.service = service_instance
        self.default_batch_size = default_batch_size

    def process_upload_session(
        self,
        upload_id: str,
        batch_size: Optional[int] = None,
        max_batches_to_run: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes or resumes streaming processing for an upload session.
        If max_batches_to_run is specified, halts after that many batches (for test simulation).
        """
        batch_size = batch_size or self.default_batch_size
        session = db.get_upload_session(upload_id)
        if not session:
            raise ValueError(f"Upload session '{upload_id}' not found.")

        staging_dir = get_upload_dir(upload_id)
        source_val = session.get("source_csv")
        upload_dir = staging_dir
        if source_val:
            source_p = Path(source_val)
            if source_p.is_file():
                upload_dir = source_p.parent
            elif source_p.is_dir():
                upload_dir = source_p

        source_csv = upload_dir / "source.csv"
        sorted_csv = upload_dir / "sorted_source.csv"

        if not source_csv.exists() and not sorted_csv.exists() and staging_dir != upload_dir:
            if (staging_dir / "source.csv").exists() or (staging_dir / "sorted_source.csv").exists():
                upload_dir = staging_dir
                source_csv = upload_dir / "source.csv"
                sorted_csv = upload_dir / "sorted_source.csv"

        if not source_csv.exists() and not sorted_csv.exists():
            raise FileNotFoundError(f"Source file not found for upload {upload_id} in {upload_dir}. Staging directory is missing or was purged.")

        try:
            return self._process_upload_session_impl(
                session=session,
                source_csv=source_csv,
                sorted_csv=sorted_csv,
                upload_id=upload_id,
                batch_size=batch_size,
                max_batches_to_run=max_batches_to_run
            )
        except Exception as e:
            db.update_upload_status(upload_id, processing_status="FAILED", error_message=str(e))
            raise

    def _process_upload_session_impl(
        self,
        session: Dict[str, Any],
        source_csv: Path,
        sorted_csv: Path,
        upload_id: str,
        batch_size: int,
        max_batches_to_run: Optional[int]
    ) -> Dict[str, Any]:
        # -------------------------------------------------------------
        # Step 0: Pre-Flight Schema Detection & Routing
        # -------------------------------------------------------------
        try:
            head_chunk = pd.read_csv(source_csv, nrows=5)
            head_cols = [clean_column_name(c) for c in head_chunk.columns]
        except Exception:
            head_cols = []

        if all(bp in head_cols for bp in PROFILE_COLS):
            # Preaggregated Event Profile CSV:
            # Delegate directly to the existing supported profile-processing service path!
            db.update_upload_status(upload_id, sort_status="SKIPPED", processing_status="PROCESSING")
            with open(source_csv, "rb") as f:
                file_bytes = f.read()
            summary = self.service.process_file_upload(
                file_bytes=file_bytes,
                filename=session["filename"],
                session_id=session["session_id"]
            )
            actual_profiles_count = len(summary.get("sample_results", []))
            total_prof = summary.get("total_records") or summary.get("total_processed") or actual_profiles_count
            db.update_upload_status(upload_id, processing_status="COMPLETED")
            db.update_upload_progress(upload_id, total_rows=total_prof, total_batches=1, completed_batches=1)
            return {
                "upload_id": upload_id,
                "session_id": session["session_id"],
                "status": "COMPLETED",
                "summary": summary
            }

        # Validate that raw flow CSV has timestamp column before sorting
        if "timestamp" not in head_cols:
            err_msg = (
                f"CSV validation failed: Uploaded file '{session['filename']}' is missing required column 'timestamp'. "
                f"A valid raw network flow CSV must contain a 'timestamp' column for temporal sliding windows. "
                f"Found columns: {head_cols[:8]}"
            )
            db.update_upload_status(upload_id, processing_status="FAILED", error_message=err_msg)
            raise InvalidTimestampError(err_msg)

        # -------------------------------------------------------------
        # Step 1: Ensure Global Chronological Ordering (External Sort)
        # -------------------------------------------------------------
        if session["sort_status"] != "SORTED" or not sorted_csv.exists():
            db.update_upload_status(upload_id, sort_status="SORTING", processing_status="PROCESSING")
            sort_meta = external_sort_csv(source_csv, sorted_csv, chunk_size=max(50000, batch_size))
            total_rows = sort_meta["total_rows"]
            global_t0_str = sort_meta["global_t0"]
            total_batches = math.ceil(total_rows / batch_size) if total_rows > 0 else 1

            db.update_upload_status(upload_id, sort_status="SORTED")
            db.update_upload_progress(
                upload_id,
                total_rows=total_rows,
                total_batches=total_batches,
                global_t0=global_t0_str
            )
            session = db.get_upload_session(upload_id)

        total_rows = session["total_rows"]
        total_batches = math.ceil(total_rows / batch_size) if total_rows > 0 else 1
        global_t0 = pd.Timestamp(session["global_t0"])
        step_seconds = self.service.aggregator.step_seconds
        window_bins = self.service.aggregator.window_bins
        window_size_seconds = self.service.aggregator.window_size_seconds

        # -------------------------------------------------------------
        # Step 2: Checkpoint Inspection and State Restoration
        # -------------------------------------------------------------
        latest_chk = db.get_latest_checkpoint(upload_id)
        completed_checkpoints = db.get_all_checkpoints(upload_id)

        if latest_chk:
            start_batch_idx = latest_chk["batch_index"] + 1
            current_row_offset = latest_chk["row_end"]
            last_finalized_k = latest_chk["last_finalized_k"]
            # Restore boundary buffer
            b_state_str = latest_chk.get("boundary_state", "{}")
            boundary_state = json.loads(b_state_str) if b_state_str else {}
            boundary_flows_records = boundary_state.get("flows", [])
            df_boundary = pd.DataFrame(boundary_flows_records) if boundary_flows_records else pd.DataFrame()
            if not df_boundary.empty:
                df_boundary["timestamp"] = pd.to_datetime(df_boundary["timestamp"])
            metrics_snapshot = json.loads(latest_chk.get("metrics_snapshot", "{}"))
        else:
            start_batch_idx = 0
            current_row_offset = 0
            last_finalized_k = -1
            df_boundary = pd.DataFrame()
            metrics_snapshot = {
                "total_event_sets": 0,
                "normal_event_sets": 0,
                "known_threats": 0,
                "unknown_anomalous": 0,
                "severity_dist": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                "attack_types": {},
                "fcnn_sum": 0.0,
                "cnn_sum": 0.0,
                "lstm_sum": 0.0,
                "ensemble_sum": 0.0
            }

        db.update_upload_status(upload_id, processing_status="PROCESSING")

        # -------------------------------------------------------------
        # Step 3: Stream Process Incomplete Batches
        # -------------------------------------------------------------
        batches_run_this_call = 0

        for batch_idx in range(start_batch_idx, total_batches):
            if max_batches_to_run is not None and batches_run_this_call >= max_batches_to_run:
                # Halt batch processing early for test simulation / pause
                db.update_upload_status(upload_id, processing_status="PAUSED")
                return {
                    "upload_id": upload_id,
                    "status": "PAUSED",
                    "completed_batches": batch_idx,
                    "total_batches": total_batches,
                    "processed_rows": current_row_offset,
                    "message": f"Paused after executing {batches_run_this_call} batch(es)."
                }

            # Check if processing was requested to pause or halt asynchronously by API
            chk_status = db.get_upload_session(upload_id)
            if chk_status and chk_status.get("processing_status") in ("PAUSED", "CANCELLED"):
                logger.info(f"Worker for '{upload_id}' halting batch loop due to {chk_status['processing_status']} status.")
                return {
                    "upload_id": upload_id,
                    "status": chk_status["processing_status"],
                    "completed_batches": batch_idx,
                    "total_batches": total_batches,
                    "processed_rows": current_row_offset,
                    "message": f"Halted after executing {batches_run_this_call} batch(es) due to {chk_status['processing_status']} request."
                }

            b_start_row = batch_idx * batch_size
            b_num_rows = min(batch_size, total_rows - b_start_row)
            is_terminal_batch = (batch_idx == total_batches - 1) or (b_start_row + b_num_rows >= total_rows)

            # Read batch rows from sorted CSV without dropping rows or reading header as data
            # Line 0 is header; skiprows=range(1, b_start_row + 1) skips the preceding data rows
            df_chunk = pd.read_csv(
                sorted_csv,
                skiprows=range(1, b_start_row + 1),
                nrows=b_num_rows,
                low_memory=False
            )

            if df_chunk.empty and not is_terminal_batch:
                continue

            # Standardize and deduplicate
            df_chunk = normalize_and_deduplicate_dataframe(df_chunk)
            df_chunk["timestamp"] = pd.to_datetime(df_chunk["timestamp"], errors="coerce")
            df_chunk = df_chunk.dropna(subset=["timestamp"]).reset_index(drop=True)

            # Ensure numeric fields are cast
            numeric_cols = ["flow_duration", "flow_packets_s", "flow_bytes_s", "syn_flag_count"]
            for c in numeric_cols:
                if c in df_chunk.columns:
                    df_chunk[c] = pd.to_numeric(df_chunk[c], errors="coerce").fillna(0.0)

            # Combine with boundary flows from previous batch
            if not df_boundary.empty:
                df_combined = pd.concat([df_boundary, df_chunk], ignore_index=True)
            else:
                df_combined = df_chunk.copy()

            if df_combined.empty:
                continue

            # Compute bins relative to the GLOBAL t0
            bins, _ = compute_bins(df_combined["timestamp"], step_seconds)
            # Override: compute bins strictly from the global anchor t0
            bins = ((df_combined["timestamp"] - global_t0) // pd.Timedelta(seconds=step_seconds)).to_numpy(dtype="int64")
            b_max = int(bins.max()) if len(bins) > 0 else -1
            n_bins = b_max + 1

            # Determine finalized window cutoff and validity
            if n_bins < window_bins:
                if is_terminal_batch:
                    raise InsufficientTemporalSpanError(
                        f"Dataset spans only {n_bins} time bin(s), fewer than one 10-minute window ({window_bins} bins required)."
                    )
                target_finalized_k = -1
                agg_batch = pd.DataFrame()
            else:
                if is_terminal_batch:
                    target_finalized_k = b_max - 9
                else:
                    # In intermediate batches, the trailing bin b_max is still open and receiving flows in the next batch.
                    # The highest complete and closed bin is b_max - 1.
                    target_finalized_k = (b_max - 1) - 9

                # Build valid windows mask for continuous operational stream
                names = np.array(["operational"] * n_bins, dtype=object)
                valid, window_split = valid_windows(names, window_bins)
                n_windows = len(valid)

                # Directional grouping
                pair_series = df_combined.groupby(["source_ip", "destination_ip"], sort=False).ngroup()
                pair_idx = pair_series.to_numpy(dtype="int64")
                unique_pairs_df = df_combined.assign(pair=pair_idx).drop_duplicates("pair")[["pair", "source_ip", "destination_ip"]]
                pair_to_ips = dict(zip(unique_pairs_df["pair"], zip(unique_pairs_df["source_ip"], unique_pairs_df["destination_ip"])))

                # Flow event rules against frozen thresholds
                flow_flags = apply_flow_events(df_combined, self.service.aggregator.thresholds)
                flow_values = np.column_stack([np.ones(len(df_combined), dtype="int64"), flow_flags.astype("int64")])

                # Window aggregation
                agg = aggregate_to_windows(pair_idx, bins, flow_values, window_bins, valid, n_windows)
                agg = agg.sort_values(["k", "pair"], kind="stable").reset_index(drop=True)

                # Filter for windows to finalize in THIS batch:
                # Must be strictly greater than last_finalized_k and <= target_finalized_k
                if not agg.empty and target_finalized_k >= (last_finalized_k + 1):
                    mask_finalize = (agg["k"] > last_finalized_k) & (agg["k"] <= target_finalized_k)
                    agg_batch = agg[mask_finalize].copy().reset_index(drop=True)
                else:
                    agg_batch = pd.DataFrame()

            batch_detections = []
            batch_alert_windows = []
            n_batch_sets = 0

            if not agg_batch.empty:
                cap_sets = pd.DataFrame({
                    "pair": agg_batch["pair"].to_numpy(dtype="int64"),
                    "k": agg_batch["k"].to_numpy(dtype="int64"),
                    "n_flows": agg_batch["v0"].to_numpy(dtype="int64")
                })
                for j, (name, _, _) in enumerate(FLOW_EVENT_SPECS, start=1):
                    cap_sets[name] = agg_batch[f"v{j}"].to_numpy(dtype="int64")

                cap_sets["split"] = window_split[cap_sets["k"].to_numpy()]
                cap_sets["window_start"] = global_t0 + pd.to_timedelta(cap_sets["k"].to_numpy() * step_seconds, unit="s")
                cap_sets["window_end"] = cap_sets["window_start"] + pd.Timedelta(seconds=window_size_seconds)

                n_batch_sets = len(cap_sets)
                session_prefix = session["session_id"].split("-")[-1]

                ips = [pair_to_ips[p] for p in cap_sets["pair"]]
                cap_sets["source_ip"] = [ip[0] for ip in ips]
                cap_sets["destination_ip"] = [ip[1] for ip in ips]

                # HIGH_FLOW_RATE evaluation
                hfr_thresh = self.service.aggregator.thresholds["HIGH_FLOW_RATE"]["threshold"]
                hfr_comp = self.service.aggregator.thresholds["HIGH_FLOW_RATE"]["comparison"]
                cap_sets["HIGH_FLOW_RATE"] = compare(cap_sets["n_flows"].to_numpy(dtype="float64"), hfr_thresh, hfr_comp).astype("int64")

                # TF-IDF & Basepoint Projection
                counts_matrix = cap_sets[EVENT_NAMES].to_numpy(dtype="int64")
                tfidf = transform(counts_matrix, self.service.aggregator.tfidf_model)
                profiles = compute_profiles(tfidf, self.service.aggregator.basepoints)

                # Batch Vectorized Inference
                preds = self.service.engine.predict_profiles_batch(profiles)

                # Map attributed flow indices within the combined slice
                # (For campaign coalescence)
                combined_timestamps = df_combined["timestamp"].to_numpy()
                combined_source_rows = df_combined["source_row"].to_numpy() if "source_row" in df_combined.columns else np.arange(len(df_combined))

                for i in range(n_batch_sets):
                    row_es = cap_sets.iloc[i]
                    p = preds[i]
                    verdict = p["verdict"]
                    status = p.get("prediction_status", verdict)
                    conf = float(p.get("threat_confidence", p.get("confidence", 0.0)))
                    cat = p.get("predicted_class", "Benign Network Traffic")
                    sev = p.get("severity", "LOW")

                    es_id = f"ES-{session_prefix}-B{batch_idx:03d}-{i+1:05d}"
                    w_id = f"W{int(row_es['k']):05d}"
                    det_id = f"DET-{session_prefix}-B{batch_idx:03d}-{i+1:05d}"

                    # Flow attribution within window interval
                    w_start = row_es["window_start"]
                    w_end = row_es["window_end"]
                    mask_in_w = (
                        (df_combined["source_ip"] == row_es["source_ip"]) &
                        (df_combined["destination_ip"] == row_es["destination_ip"]) &
                        (df_combined["timestamp"] >= w_start) &
                        (df_combined["timestamp"] < w_end)
                    )
                    attr_source_rows = combined_source_rows[mask_in_w].tolist()

                    det_record = {
                        "id": det_id,
                        "session_id": session["session_id"],
                        "timestamp": str(row_es["window_start"]),
                        "source": session["filename"],
                        "input_type": "flow",
                        "source_ip": str(row_es["source_ip"]),
                        "destination_ip": str(row_es["destination_ip"]),
                        "destination_port": 0,
                        "protocol": "TCP",
                        "verdict": verdict,
                        "prediction_status": status,
                        "predicted_class": cat,
                        "confidence": conf,
                        "threat_confidence": conf,
                        "threat_type": cat,
                        "severity": sev,
                        "dominant_basepoint": p.get("dominant_basepoint", "bp_01"),
                        "dominant_similarity": round(float(p.get("dominant_basepoint_similarity", 0.0)), 4),
                        "profile_vector": profiles[i].tolist(),
                        "model_breakdown": p.get("model_breakdown", {}),
                        "anomaly_verdict": p.get("anomaly", {}).get("verdict", "NORMAL") if p.get("anomaly") else "NORMAL",
                        "anomaly_status": p.get("anomaly_status", "NORMAL"),
                        "anomaly_score": float(p.get("anomaly", {}).get("anomaly_score", 0.0)) if p.get("anomaly") else 0.0,
                        "detection_reason": p.get("detection_reason", ""),
                        "requires_investigation": bool(p.get("requires_investigation", False)),
                        "campaign_id": "-",
                        "flow_metadata": {
                            "window_id": w_id,
                            "event_set_id": es_id,
                            "k": int(row_es["k"]),
                            "n_flows": int(row_es["n_flows"]),
                            "window_start": str(row_es["window_start"]),
                            "window_end": str(row_es["window_end"])
                        }
                    }
                    batch_detections.append(det_record)

                    # If alerting window, record for global campaign coalescence
                    if verdict in ("KNOWN_THREAT", "UNKNOWN_ANOMALOUS"):
                        batch_alert_windows.append({
                            "event_set_id": es_id,
                            "window_dict": {
                                "event_set_id": es_id,
                                "window_id": w_id,
                                "k": int(row_es["k"]),
                                "source_ip": str(row_es["source_ip"]),
                                "destination_ip": str(row_es["destination_ip"]),
                                "window_start": str(row_es["window_start"]),
                                "window_end": str(row_es["window_end"]),
                                "verdict": verdict,
                                "confidence": conf,
                                "ensemble_score": float(p.get("ensemble_score", conf)),
                                "anomaly_score": float(p.get("anomaly", {}).get("anomaly_score", 0.0)) if p.get("anomaly") else 0.0,
                                "basepoint_profile": profiles[i].tolist()
                            },
                            "flow_indices": attr_source_rows
                        })

                    # Update running metrics
                    metrics_snapshot["total_event_sets"] += 1
                    if verdict == "NORMAL":
                        metrics_snapshot["normal_event_sets"] += 1
                    elif verdict == "KNOWN_THREAT":
                        metrics_snapshot["known_threats"] += 1
                    elif verdict == "UNKNOWN_ANOMALOUS":
                        metrics_snapshot["unknown_anomalous"] += 1
                    metrics_snapshot["severity_dist"][sev] = metrics_snapshot["severity_dist"].get(sev, 0) + 1
                    metrics_snapshot["attack_types"][cat] = metrics_snapshot["attack_types"].get(cat, 0) + 1

                # Numerically stable probability accumulation across finalized batch event sets
                if n_batch_sets > 0:
                    f_batch = [float(p.get("model_breakdown", {}).get("fcnn", 0.0)) for p in preds]
                    c_batch = [float(p.get("model_breakdown", {}).get("cnn", 0.0)) for p in preds]
                    l_batch = [float(p.get("model_breakdown", {}).get("lstm", 0.0)) for p in preds]
                    ens_batch = [float(p.get("threat_confidence", p.get("confidence", 0.0))) for p in preds]

                    metrics_snapshot["fcnn_sum"] = metrics_snapshot.get("fcnn_sum", 0.0) + math.fsum(f_batch)
                    metrics_snapshot["cnn_sum"] = metrics_snapshot.get("cnn_sum", 0.0) + math.fsum(c_batch)
                    metrics_snapshot["lstm_sum"] = metrics_snapshot.get("lstm_sum", 0.0) + math.fsum(l_batch)
                    metrics_snapshot["ensemble_sum"] = metrics_snapshot.get("ensemble_sum", 0.0) + math.fsum(ens_batch)

            if target_finalized_k >= (last_finalized_k + 1):
                last_finalized_k = max(last_finalized_k, target_finalized_k)

            # Prepare next boundary buffer:
            # Trailing flows starting from the earliest bin needed for pending windows
            if not is_terminal_batch:
                # Pending windows start at last_finalized_k + 1
                boundary_start_t = global_t0 + pd.Timedelta(seconds=step_seconds * (last_finalized_k + 1))
                mask_boundary = df_combined["timestamp"] >= boundary_start_t
                df_next_boundary = df_combined[mask_boundary].copy()

                # Limit boundary buffer strictly to string-serializable records
                boundary_records = df_next_boundary.to_dict(orient="records")
                for r in boundary_records:
                    if isinstance(r.get("timestamp"), pd.Timestamp):
                        r["timestamp"] = r["timestamp"].isoformat()
                boundary_state_json = json.dumps({"flows": boundary_records})
                df_boundary = df_next_boundary
            else:
                boundary_state_json = json.dumps({"flows": []})
                df_boundary = pd.DataFrame()

            # Atomically save batch checkpoint & intermediate detections
            current_row_offset = b_start_row + len(df_chunk)
            db.save_batch_checkpoint(
                upload_id=upload_id,
                batch_index=batch_idx,
                row_start=b_start_row,
                row_end=current_row_offset,
                n_flows=len(df_chunk),
                n_event_sets=n_batch_sets,
                last_finalized_k=last_finalized_k,
                boundary_state=boundary_state_json,
                metrics_snapshot=json.dumps(metrics_snapshot),
                detections_list=batch_detections,
                alert_windows_list=batch_alert_windows
            )

            batches_run_this_call += 1

            # Explicit garbage collection after each batch
            del df_chunk, df_combined
            gc.collect()

        # -------------------------------------------------------------
        # Step 4: Terminal Finalization (Global Campaign Coalescence)
        # -------------------------------------------------------------
        all_alert_rows = db.get_pending_alert_windows(upload_id)
        all_window_predictions = [r["window"] for r in all_alert_rows]
        all_flow_attributions = {r["event_set_id"]: r["flow_indices"] for r in all_alert_rows}

        coalesced = coalesce_campaigns(
            window_predictions=all_window_predictions,
            flow_attributions=all_flow_attributions,
            session_id=session["session_id"],
            window_bins=window_bins,
            step_seconds=step_seconds
        )
        campaigns = coalesced["campaigns"]
        campaign_stats = coalesced["campaign_statistics"]
        event_set_stats = coalesced["event_set_statistics"]
        flow_stats = coalesced["flow_statistics"]

        # Map campaign IDs back to intermediate detections
        window_to_camp = {}
        for camp in campaigns:
            c_id = camp.get("campaign_id")
            for es_id in camp.get("constituent_event_set_ids", []):
                window_to_camp[es_id] = c_id
            for w_id in camp.get("constituent_windows", []):
                window_to_camp[w_id] = c_id

        all_intermediate_detections = db.get_intermediate_detections(upload_id)
        for det in all_intermediate_detections:
            f_meta = det.get("flow_metadata", {})
            w_id = f_meta.get("window_id") or det.get("id")
            es_id = f_meta.get("event_set_id") or ""
            c_id = window_to_camp.get(es_id, window_to_camp.get(w_id, "-"))
            det["campaign_id"] = c_id

        # Master Session Summary
        total_event_sets = metrics_snapshot["total_event_sets"]
        normal_count = metrics_snapshot["normal_event_sets"]
        known_threat_event_sets = metrics_snapshot.get("known_threats", 0)
        unknown_anomalous_event_sets = metrics_snapshot.get("unknown_anomalous", 0)

        threat_count = campaign_stats.get("total_campaigns", 0)
        known_threat_count = campaign_stats.get("known_threat_campaigns", 0)
        unknown_anomalous_count = campaign_stats.get("unknown_anomalous_campaigns", 0)
        threat_ratio = round((threat_count / max(total_event_sets, 1)) * 100, 2)

        # Normalize full-session summary statistics after campaign coalescence
        # flow_statistics: total_raw_flows represents all uploaded raw flows
        flow_stats["total_raw_flows"] = total_rows

        # event_set_statistics: represents all generated event sets across full capture
        event_set_stats["total_event_sets"] = total_event_sets
        event_set_stats["normal_event_sets"] = normal_count
        event_set_stats["ann_alert_sets"] = known_threat_event_sets
        event_set_stats["unknown_anomalous_sets"] = unknown_anomalous_event_sets

        total_evaluated_sets = metrics_snapshot["total_event_sets"]
        if total_evaluated_sets > 0:
            fcnn_avg = round(metrics_snapshot.get("fcnn_sum", 0.0) / total_evaluated_sets, 4)
            cnn_avg = round(metrics_snapshot.get("cnn_sum", 0.0) / total_evaluated_sets, 4)
            lstm_avg = round(metrics_snapshot.get("lstm_sum", 0.0) / total_evaluated_sets, 4)
            ensemble_avg = round(metrics_snapshot.get("ensemble_sum", 0.0) / total_evaluated_sets, 4)
        else:
            fcnn_avg, cnn_avg, lstm_avg, ensemble_avg = 0.0, 0.0, 0.0, 0.0

        summary = {
            "session_id": session["session_id"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_name": session["filename"],
            "input_type": "flow",
            "total_records": total_rows,
            "total_processed": total_event_sets,
            "normal_events": normal_count,
            "threats_detected": threat_count,
            "known_threats": known_threat_count,
            "ann_alerts": known_threat_count,
            "unknown_anomalous": unknown_anomalous_count,
            "known_threat_event_sets": known_threat_event_sets,
            "unknown_anomalous_event_sets": unknown_anomalous_event_sets,
            "invalid_records": 0,
            "threat_ratio": threat_ratio,
            "threat_percentage": threat_ratio,
            "severity_distribution": metrics_snapshot["severity_dist"],
            "attack_categories": metrics_snapshot["attack_types"],
            "dominant_attack_types": metrics_snapshot["attack_types"],
            "model_summary": {
                "fcnn_avg": fcnn_avg,
                "cnn_avg": cnn_avg,
                "lstm_avg": lstm_avg,
                "ensemble_avg": ensemble_avg,
                "fcnn_alerts": known_threat_event_sets,
                "cnn_alerts": known_threat_event_sets,
                "lstm_alerts": known_threat_event_sets,
                "ensemble_alerts": known_threat_count,
                "isolation_forest_anomalies": unknown_anomalous_count
            },
            "flow_statistics": flow_stats,
            "event_set_statistics": event_set_stats,
            "campaign_statistics": campaign_stats,
            "sample_results": all_intermediate_detections[:50]
        }

        # Compute Dual-Layer Data Drift Analysis for finalized streaming session
        try:
            from src.drift import DriftEngine
            drift_engine = DriftEngine()

            df_flows_drift = None
            if sorted_csv.exists():
                try:
                    cols_head = pd.read_csv(sorted_csv, nrows=1).columns.tolist()
                    drift_cols = [c for c in ["flow_duration", "flow_bytes_s", "flow_packets_s", "syn_flag_count"] if c in cols_head]
                    if drift_cols:
                        df_flows_drift = pd.read_csv(sorted_csv, usecols=drift_cols, nrows=100000)
                except Exception as e_csv:
                    logger.warning(f"Could not read raw features for drift from sorted CSV: {e_csv}")

            profiles_matrix_drift = None
            if all_intermediate_detections:
                p_vecs = [d.get("profile_vector") for d in all_intermediate_detections if d.get("profile_vector")]
                if p_vecs:
                    profiles_matrix_drift = np.array(p_vecs, dtype=np.float32)

            if df_flows_drift is not None or profiles_matrix_drift is not None:
                drift_rep = drift_engine.evaluate_drift(
                    df_flows=df_flows_drift,
                    profiles_matrix=profiles_matrix_drift,
                    session_id=session["session_id"],
                    upload_id=upload_id
                )
                summary["drift_analysis"] = drift_rep
        except Exception as e_drift:
            logger.warning(f"Streaming drift evaluation error: {e_drift}")

        # Atomically commit final master session, move detections, insert campaigns
        db.finalize_upload_session(
            upload_id=upload_id,
            session_summary=summary,
            coalesced_campaigns=campaigns,
            final_detections=all_intermediate_detections
        )

        # Update singleton service active view
        self.service.latest_completed_session_id = session["session_id"]
        self.service.current_analysis_summary = summary

        return {
            "upload_id": upload_id,
            "session_id": session["session_id"],
            "status": "COMPLETED",
            "summary": summary
        }
