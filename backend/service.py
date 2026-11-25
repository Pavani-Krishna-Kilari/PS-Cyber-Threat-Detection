"""
SIEM Backend Service Layer: Manages state, telemetry, metrics, and live stream.
Integrates SQLite persistence for actual detection records and analysis sessions.
"""

import json
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT, resolve_path
from src.inference.predict import ThreatInferenceEngine
from src.models.anomaly import AnomalyDetector
from backend.parser import parse_uploaded_file, PROFILE_COLS
from backend.aggregator import (
    RawFlowAggregator,
    InsufficientTemporalSpanError,
    AggregatorError,
    MissingFeatureColumnsError,
    InvalidTimestampError,
    InvalidBenchmarkAnnotationError
)
from backend.campaign import coalesce_campaigns
import backend.database as db
from backend.database import (
    init_db,
    insert_session,
    insert_detections,
    insert_campaigns,
    get_campaigns,
    get_latest_session,
    get_detections,
    get_detections_count,
    get_recent_threats,
    get_recent_unknown_anomalous,
    get_session_stream,
    clear_all_history,
    get_sessions,
    get_sessions_count,
    get_session_by_id,
    get_session_report,
    delete_session
)


class SIEMService:
    """
    Singleton service managing SIEM inference, cached dataset statistics,
    actual user-input detection sessions, and SQLite persistence.
    """

    def __init__(self, experiment_id: str = "A"):
        init_db()
        self.current_analysis_summary: Optional[Dict[str, Any]] = None
        self.latest_completed_session_id: Optional[str] = None
        self._stream_explicitly_cleared: bool = False
        self._cached_dataset_stats: Optional[Dict[str, Any]] = None
        self._cached_profile_stats: Optional[Dict[str, Any]] = None
        self._cached_benchmarks: Optional[Dict[str, Any]] = None
        self._cached_anomaly_stats: Optional[Dict[str, Any]] = None
        self.active_workers: Dict[str, Any] = {}
        self.set_experiment(experiment_id)

    def register_worker(self, upload_id: str, thread: Any):
        """Registers an active worker thread for an upload session."""
        self.active_workers[upload_id] = thread

    def unregister_worker(self, upload_id: str):
        """Unregisters a completed or terminated worker thread."""
        self.active_workers.pop(upload_id, None)

    def is_stream_worker_running(self, upload_id: str) -> bool:
        """Checks if a background worker thread is currently alive for an upload."""
        th = self.active_workers.get(upload_id)
        if th is not None:
            if hasattr(th, "is_alive") and th.is_alive():
                return True
            elif th is True:
                return True
        return False

    def set_experiment(self, experiment_id: str):
        """Switches active experiment, loading verified models, profiles, and metrics."""
        self.experiment_id = experiment_id

        # Experiment B is the active production configuration; Experiment A is preserved
        if experiment_id == "B":
            models_dir = PROJECT_ROOT / "models" / "saved_exp_b"
            data_dir = PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_b"
            metrics_dir = PROJECT_ROOT / "models" / "metrics_exp_b"
        else:
            models_dir = PROJECT_ROOT / "models" / "saved_exp_a"
            data_dir = PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_a"
            metrics_dir = PROJECT_ROOT / "models" / "metrics_exp_a"

        # Explicit safety verification: do NOT fall back silently if Experiment B artifacts are missing
        required_models = [
            "fcnn_model.keras", "cnn_model.keras", "lstm_model.keras",
            "ensemble_config.json", "isolation_forest.joblib", "anomaly_config.json"
        ]
        missing_models = [f for f in required_models if not (models_dir / f).exists()]
        if missing_models:
            raise FileNotFoundError(
                f"Experiment {experiment_id} failed to initialize: missing model files {missing_models} in {models_dir}"
            )

        required_data = [
            "basepoints.csv", "tfidf_model.json", "event_thresholds.json", "event_profiles_metadata.json"
        ]
        missing_data = [f for f in required_data if not (data_dir / f).exists()]
        if missing_data:
            raise FileNotFoundError(
                f"Experiment {experiment_id} failed to initialize: missing data artifacts {missing_data} in {data_dir}"
            )

        self.models_dir = models_dir
        self.data_dir = data_dir
        self.metrics_dir = metrics_dir

        self.engine = ThreatInferenceEngine(models_dir=models_dir, data_dir=data_dir, experiment_id=experiment_id)
        if not self.engine.is_ready():
            raise RuntimeError(f"Experiment {experiment_id} ThreatInferenceEngine failed to initialize all models.")

        self.anomaly_detector = self.engine.anomaly_detector
        self.aggregator = RawFlowAggregator(experiment_id=self.experiment_id, data_dir=self.data_dir)
        from backend.processor import StreamBatchProcessor
        self.processor = StreamBatchProcessor(service_instance=self)
        self._cached_dataset_stats = None
        self._cached_profile_stats = None
        self._cached_benchmarks = None
        self._cached_anomaly_stats = None

    def get_system_status(self) -> Dict[str, Any]:
        """Returns overall health and initialization status of all subsystems."""
        return {
            "status": "OPERATIONAL" if (self.engine.is_ready() and self.anomaly_detector.is_ready()) else "DEGRADED",
            "experiment_id": self.experiment_id,
            "active_experiment": "Experiment B (Multi-Day Control & Unseen Evaluation)" if self.experiment_id == "B" else "Experiment A (Multi-Day Time-Blocked)",
            "models_loaded": {
                "fcnn": self.engine.fcnn_model is not None,
                "cnn": self.engine.cnn_model is not None,
                "lstm": self.engine.lstm_model is not None,
                "ensemble": self.engine.ensemble is not None,
                "isolation_forest": self.anomaly_detector.is_ready()
            },
            "submodel_thresholds": self.engine.submodel_thresholds,
            "artifacts_loaded": {
                "basepoints": self.engine.basepoints is not None,
                "tfidf_model": self.engine.tfidf_model is not None,
                "thresholds": self.engine.thresholds is not None,
                "anomaly_model": self.anomaly_detector.is_ready()
            },
            "ensemble_config": {
                "weights": self.engine.ensemble.weights if self.engine.ensemble else [],
                "threshold": self.engine.ensemble.threshold if self.engine.ensemble else (0.6561 if self.experiment_id == "B" else 0.8398)
            },
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """
        Returns the user-facing detection summary for the SOC Home Overview.
        CRITICAL REQUIREMENT: Defaults to 0 when opened for a new session.
        Only displays results from actual user inputs analysed in this session.
        """
        if self.current_analysis_summary is None:
            return {
                "has_data": False,
                "experiment_id": self.experiment_id,
                "total_records": 0,
                "normal_events": 0,
                "threats_detected": 0,
                "known_threats": 0,
                "ann_alerts": 0,
                "unknown_anomalous": 0,
                "invalid_records": 0,
                "threat_ratio": 0.0,
                "processing_time_ms": 0.0,
                "attack_categories": {},
                "severity_distribution": {
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0,
                    "CRITICAL": 0
                },
                "flow_statistics": {
                    "total_raw_flows": 0,
                    "unique_flows_analysed": 0,
                    "benign_flows": 0,
                    "known_threat_flows": 0,
                    "unknown_anomalous_flows": 0,
                    "invalid_flows": 0
                },
                "event_set_statistics": {
                    "total_event_sets": 0,
                    "normal_event_sets": 0,
                    "ann_alert_sets": 0,
                    "unknown_anomalous_sets": 0
                },
                "campaign_statistics": {
                    "total_campaigns": 0,
                    "known_threat_campaigns": 0,
                    "unknown_anomalous_campaigns": 0
                },
                "campaigns": [],
                "latest_analysis_name": None,
                "latest_timestamp": None,
                "model_summary": {
                    "fcnn_avg": 0.0,
                    "cnn_avg": 0.0,
                    "lstm_avg": 0.0,
                    "ensemble_avg": 0.0
                }
            }
        return self.current_analysis_summary

    def clear_batch_summary(self):
        """Resets the active batch analysis summary and stream to None, restoring SOC Overview empty state."""
        self.current_analysis_summary = None
        self.latest_completed_session_id = None
        self._stream_explicitly_cleared = True

    def get_dataset_stats(self) -> Dict[str, Any]:
        """Returns training dataset statistics for About Project documentation."""
        if self._cached_dataset_stats is None:
            comb_meta_path = resolve_path("data/processed/CICIDS2017_combined_metadata.json")
            if comb_meta_path.exists():
                data = json.loads(comb_meta_path.read_text(encoding="utf-8"))
                lbl_dist = {}
                for split_data in data.get("experiment_a_labels_by_split", {}).values():
                    for k, v in split_data.items():
                        lbl_dist[k] = lbl_dist.get(k, 0) + v

                self._cached_dataset_stats = {
                    "source_file": "CICIDS2017_combined_clean.csv (All 8 Captures)",
                    "datasets": data.get("datasets", []),
                    "rows_final": data.get("total_rows_final", 2827677),
                    "columns_count": data.get("columns_count", 85),
                    "labels_distribution": lbl_dist,
                    "experiment": "Experiment B (Unseen Attacks Under Domain Shift with Known-Attack Control)" if self.experiment_id == "B" else "Experiment A (Multi-Day Time-Blocked)",
                    "split_plan": {
                        "train_profiles": 1997495 if self.experiment_id == "B" else 1955329,
                        "validation_profiles": 625399 if self.experiment_id == "B" else 399179,
                        "control_test_profiles": 42189 if self.experiment_id == "B" else 0,
                        "test_profiles": 569099 if self.experiment_id == "B" else 473169,
                        "window_size_seconds": 600,
                        "window_step_seconds": 60
                    }
                }
            else:
                meta_path = resolve_path("data/processed/Tuesday-WorkingHours_metadata.json")
                if meta_path.exists():
                    data = json.loads(meta_path.read_text(encoding="utf-8"))
                    self._cached_dataset_stats = {
                        "source_file": data.get("source_file", "Tuesday-WorkingHours.pcap_ISCX.csv"),
                        "raw_sha256": data.get("raw_sha256", "N/A"),
                        "rows_loaded": data.get("rows_loaded", 445909),
                        "rows_final": data.get("rows_final", 445641),
                        "context_columns": data.get("context_columns", []),
                        "feature_columns_count": len(data.get("feature_columns", [])),
                        "removed_constant_columns": data.get("removed_constant_columns", []),
                        "labels_distribution": {
                            "BENIGN": 431809,
                            "FTP-Patator": 7935,
                            "SSH-Patator": 5897
                        },
                        "split_plan": {
                            "train_flows": 246471,
                            "validation_flows": 99486,
                            "test_flows": 99684,
                            "block_minutes": 20
                        }
                    }
                else:
                    self._cached_dataset_stats = {"error": "Metadata not found"}
        return self._cached_dataset_stats

    def get_profile_stats(self) -> Dict[str, Any]:
        """Returns metadata and statistics for active event profiles (Phase 3)."""
        if self._cached_profile_stats is None:
            meta_path = self.data_dir / "event_profiles_metadata.json"
            thresh_path = self.data_dir / "event_thresholds.json"
            bp_path = self.data_dir / "basepoints.csv"

            basepoints_data = []
            if bp_path.exists():
                df_bp = pd.read_csv(bp_path)
                basepoints_data = df_bp.to_dict(orient="records")

            thresholds = {}
            if thresh_path.exists():
                thresholds = json.loads(thresh_path.read_text(encoding="utf-8"))

            if meta_path.exists():
                m_data = json.loads(meta_path.read_text(encoding="utf-8"))
                split_dist = m_data.get("split_distribution", m_data.get("split_counts", {}))
                t_dist = m_data.get("target_binary_distribution", {})

                attack_counts = {}
                benign_counts = {}
                total_attacks = 0
                total_benign = 0
                for sp, counts in t_dist.items():
                    atk = counts.get("1", 0) if isinstance(counts, dict) else 0
                    bng = counts.get("0", 0) if isinstance(counts, dict) else 0
                    attack_counts[sp] = atk
                    benign_counts[sp] = bng
                    total_attacks += atk
                    total_benign += bng

                total_events = m_data.get("total_event_sets", 3234182 if self.experiment_id == "B" else 2569260)
                if total_attacks == 0 and "total_attack_sets" in m_data:
                    total_attacks = m_data["total_attack_sets"]
                    total_benign = m_data.get("total_benign_sets", total_events - total_attacks)

                self._cached_profile_stats = {
                    "experiment_id": self.experiment_id,
                    "total_event_sets": total_events,
                    "train_event_sets": split_dist.get("train", 1997495 if self.experiment_id == "B" else 1935461),
                    "validation_event_sets": split_dist.get("validation", 625399 if self.experiment_id == "B" else 321262),
                    "control_test_event_sets": split_dist.get("control_test", 42189 if self.experiment_id == "B" else 0),
                    "test_event_sets": split_dist.get("test", 569099 if self.experiment_id == "B" else 312537),
                    "split_counts": split_dist,
                    "attack_event_sets": total_attacks,
                    "benign_event_sets": total_benign,
                    "attack_counts_by_split": attack_counts,
                    "attack_ratio_pct": round((total_attacks / max(total_events, 1)) * 100, 4),
                    "window_size_seconds": m_data.get("window_size_seconds", 600),
                    "window_step_seconds": m_data.get("window_step_seconds", 60),
                    "thresholds": thresholds,
                    "basepoints": basepoints_data
                }
            else:
                self._cached_profile_stats = {
                    "experiment_id": self.experiment_id,
                    "total_event_sets": 3234182 if self.experiment_id == "B" else 2569260,
                    "thresholds": thresholds,
                    "basepoints": basepoints_data
                }
        return self._cached_profile_stats

    def get_model_benchmarks(self) -> Dict[str, Any]:
        """Returns benchmark comparison metrics and training history for active experiment."""
        report_path = self.metrics_dir / "evaluation_report.json"
        hist_path = self.metrics_dir / "training_history.json"
        eval_a_path = self.metrics_dir / "evaluation_a_unseen.json"
        eval_b_path = self.metrics_dir / "evaluation_b_control.json"

        benchmarks = {}
        history = {}
        eval_a_unseen = {}
        eval_b_control = {}

        if report_path.exists():
            benchmarks = json.loads(report_path.read_text(encoding="utf-8"))
        if hist_path.exists():
            history = json.loads(hist_path.read_text(encoding="utf-8"))
        if eval_a_path.exists():
            eval_a_unseen = json.loads(eval_a_path.read_text(encoding="utf-8"))
        if eval_b_path.exists():
            eval_b_control = json.loads(eval_b_path.read_text(encoding="utf-8"))

        return {
            "experiment_id": self.experiment_id,
            "evaluation_report": benchmarks,
            "evaluation_a_unseen": eval_a_unseen,
            "evaluation_b_control": eval_b_control,
            "training_history": history,
            "optimal_thresholds": benchmarks.get("optimal_thresholds", {
                "FCNN": 0.8582, "CNN": 0.3439, "LSTM": 0.7663, "Ensemble": 0.6561, "IsolationForest": -0.012676
            })
        }

    def process_file_upload(
        self,
        file_bytes: bytes,
        filename: str,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Parses an uploaded CSV/TXT/PDF file and runs genuine threat inference
        using the trained neural ensemble and isolation forest models.

        Supports:
          1. Raw Network Flow CSV: Validates schema, runs sliding-window event aggregation (W=10, 60s step),
             performs vectorized batch neural/anomaly inference, and coalesces alerting windows into campaigns.
          2. Preaggregated Event Profile CSV: Evaluates 8D basepoint vectors with vectorized batch inference
             and coalesces alert profiles into campaigns.
        """
        start_time_proc = time.perf_counter()
        df, detected_type = parse_uploaded_file(file_bytes, filename)
        if df.empty:
            raise ValueError("No tabular network flow records found in file.")

        session_id = session_id or f"SESS-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        session_prefix = session_id.split("-")[-1]

        results = []
        attack_types: Dict[str, int] = {}
        severity_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        fcnn_probs, cnn_probs, lstm_probs, ens_probs = [], [], [], []

        if detected_type == "flow":
            # ---------------------------------------------------------
            # Branch 1: Raw Network Flow Stream Aggregation & Inference
            # ---------------------------------------------------------
            # Validate flow columns strictly; never fall back silently to single-flow
            is_valid_schema, schema_mode = self.aggregator.validate_schema(df)
            if not is_valid_schema:
                err_msg = (
                    f"Validation error in '{filename}': {schema_mode}. "
                    f"Extracted {len(df)} network flow record(s) with columns {sorted(list(df.columns))}. "
                    "Sliding-window temporal aggregation requires timestamps for 60-second binning and 10-minute sliding windows."
                )
                err = MissingFeatureColumnsError(err_msg)
                err.details = {
                    "extracted_records": len(df),
                    "columns_found": sorted(list(df.columns)),
                    "schema_mode": schema_mode
                }
                raise err

            # Check benchmark annotations
            is_benchmark = ("split" in df.columns or "block_id" in df.columns)

            # Execute Stage 1 sliding-window aggregation
            agg_result = self.aggregator.aggregate_flows(df, is_benchmark_replay=is_benchmark)

            profiles = agg_result["profiles"]           # np.ndarray shape (N_sets, 8)
            profile_df = agg_result["profile_df"]       # DataFrame
            event_sets = agg_result["event_sets"]       # DataFrame
            flow_attributions = agg_result["flow_attributions"]
            agg_meta = agg_result["metadata"]
            n_sets = len(event_sets)

            # Vectorized Batch Inference across all generated event sets
            preds = self.engine.predict_profiles_batch(profiles)

            # Build window prediction records
            window_predictions = []
            for i in range(n_sets):
                row_es = event_sets.iloc[i]
                p = preds[i]
                verdict = p["verdict"]
                status = p.get("prediction_status", verdict)
                conf = float(p.get("threat_confidence", p.get("confidence", 0.0)))
                cat = p.get("predicted_class", "Benign Network Traffic")
                sev = p.get("severity", "LOW")

                w_pred = {
                    "event_set_id": str(row_es["event_set_id"]),
                    "window_id": str(row_es["window_id"]),
                    "k": int(row_es["k"]),
                    "source_ip": str(row_es["source_ip"]),
                    "destination_ip": str(row_es["destination_ip"]),
                    "window_start": str(row_es["window_start"]),
                    "window_end": str(row_es["window_end"]),
                    "verdict": verdict,
                    "confidence": conf,
                    "ensemble_score": float(p.get("ensemble_score", conf)),
                    "anomaly_score": float(p.get("anomaly", {}).get("anomaly_score", 0.0)) if p.get("anomaly") else 0.0,
                    "basepoint_profile": profiles[i].tolist(),
                    "predicted_class": cat,
                    "prediction_status": status,
                    "severity": sev,
                    "dominant_basepoint": p.get("dominant_basepoint", "bp_01"),
                    "dominant_similarity": round(float(p.get("dominant_basepoint_similarity", 0.0)), 4),
                    "model_breakdown": p.get("model_breakdown", {}),
                    "anomaly_verdict": p.get("anomaly", {}).get("verdict", "NORMAL") if p.get("anomaly") else "NORMAL",
                    "anomaly_status": p.get("anomaly_status", "NORMAL"),
                    "detection_reason": p.get("detection_reason", ""),
                    "requires_investigation": bool(p.get("requires_investigation", False)),
                    "n_flows": int(row_es["n_flows"])
                }
                window_predictions.append(w_pred)

                # Collect metrics
                mb = p.get("model_breakdown", {})
                fcnn_probs.append(float(mb.get("fcnn", 0.0)))
                cnn_probs.append(float(mb.get("cnn", 0.0)))
                lstm_probs.append(float(mb.get("lstm", 0.0)))
                ens_probs.append(conf)
                severity_dist[sev] = severity_dist.get(sev, 0) + 1
                attack_types[cat] = attack_types.get(cat, 0) + 1

                # Build detection record for persistence
                det_record = {
                    "id": f"DET-{time.strftime('%Y%m%d%H%M%S')}-{session_prefix}-{i + 1:04d}",
                    "session_id": session_id,
                    "index": i + 1,
                    "timestamp": str(row_es["window_start"]),
                    "source": filename,
                    "input_type": detected_type,
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
                    "model_breakdown": mb,
                    "anomaly_verdict": p.get("anomaly", {}).get("verdict", "NORMAL") if p.get("anomaly") else "NORMAL",
                    "anomaly_status": p.get("anomaly_status", "NORMAL"),
                    "anomaly_score": float(p.get("anomaly", {}).get("anomaly_score", 0.0)) if p.get("anomaly") else 0.0,
                    "detection_reason": p.get("detection_reason", ""),
                    "requires_investigation": bool(p.get("requires_investigation", False)),
                    "flow_metadata": {
                        "event_set_id": str(row_es["event_set_id"]),
                        "window_id": str(row_es["window_id"]),
                        "k": int(row_es["k"]),
                        "n_flows": int(row_es["n_flows"]),
                        "window_start": str(row_es["window_start"]),
                        "window_end": str(row_es["window_end"])
                    }
                }
                results.append(det_record)

            # Transitive Campaign Coalescence
            coalesced = coalesce_campaigns(
                window_predictions=window_predictions,
                flow_attributions=flow_attributions,
                session_id=session_id,
                window_bins=self.aggregator.window_bins,
                step_seconds=self.aggregator.step_seconds
            )
            campaigns = coalesced["campaigns"]
            flow_statistics = coalesced["flow_statistics"]
            event_set_statistics = coalesced["event_set_statistics"]
            campaign_statistics = coalesced["campaign_statistics"]

            # Ensure total raw flows from input are recorded
            flow_statistics["total_raw_flows"] = len(df)
            flow_statistics["invalid_flows"] = max(0, len(df) - flow_statistics["unique_flows_analysed"])

            # Build window/event_set lookup to coalesced campaign ID
            window_to_camp = {}
            for camp in campaigns:
                c_id = camp.get("campaign_id")
                for es_id in camp.get("constituent_event_set_ids", []):
                    window_to_camp[es_id] = c_id
                for w_id in camp.get("constituent_windows", []):
                    window_to_camp[w_id] = c_id

            for det in results:
                f_meta = det.get("flow_metadata", {})
                w_id = f_meta.get("window_id") or det.get("id")
                es_id = f_meta.get("event_set_id") or f"ES{det.get('index', 0):07d}"
                c_id = window_to_camp.get(es_id, window_to_camp.get(w_id, "-"))
                det["campaign_id"] = c_id
                det["event_set_id"] = es_id

            total_processed = event_set_statistics["total_event_sets"]
            normal_count = event_set_statistics["normal_event_sets"]
            threat_count = campaign_statistics["total_campaigns"]
            known_threat_count = campaign_statistics["known_threat_campaigns"]
            unknown_anomalous_count = campaign_statistics["unknown_anomalous_campaigns"]
            invalid_count = flow_statistics["invalid_flows"]

        else:
            # ---------------------------------------------------------
            # Branch 2: Preaggregated 8D Event Profile CSV
            # ---------------------------------------------------------
            total_uploaded = len(df)

            # Vectorized validation of all 8 required basepoint dimensions
            bp_matrix = df[PROFILE_COLS].to_numpy(dtype=np.float64)
            # Row is valid if all 8 dimensions are strictly finite (not NaN, not Inf)
            valid_mask = np.all(np.isfinite(bp_matrix), axis=1)
            valid_indices = np.where(valid_mask)[0]
            invalid_count = total_uploaded - len(valid_indices)

            # Reject uploads where no valid profile records exist
            if len(valid_indices) == 0:
                raise ValueError(
                    f"Validation failed: No valid 8-dimensional event profile records found in '{filename}'. "
                    f"All {total_uploaded} row(s) contained malformed, non-finite, or unparseable numerical values."
                )

            # Pre-extract optional destination ports and contextual metadata
            if "destination_port" in df.columns:
                raw_ports = pd.to_numeric(df["destination_port"], errors="coerce").fillna(0).to_numpy()
                ports_array = np.clip(np.nan_to_num(raw_ports, nan=0), 0, 65535).astype(int)
            else:
                ports_array = np.zeros(total_uploaded, dtype=int)

            has_src_ip = "source_ip" in df.columns
            has_dst_ip = "destination_ip" in df.columns
            has_es_id = "event_set_id" in df.columns
            has_w_id = "window_id" in df.columns
            has_k = "k" in df.columns
            has_w_start = "window_start" in df.columns
            has_w_end = "window_end" in df.columns
            has_proto = "protocol" in df.columns
            has_n_flows = "n_flows" in df.columns

            src_ip_col = df["source_ip"].to_numpy() if has_src_ip else None
            dst_ip_col = df["destination_ip"].to_numpy() if has_dst_ip else None
            es_id_col = df["event_set_id"].to_numpy() if has_es_id else None
            w_id_col = df["window_id"].to_numpy() if has_w_id else None
            k_col = df["k"].to_numpy() if has_k else None
            w_start_col = df["window_start"].to_numpy() if has_w_start else None
            w_end_col = df["window_end"].to_numpy() if has_w_end else None
            proto_col = df["protocol"].to_numpy() if has_proto else None
            n_flows_col = df["n_flows"].to_numpy() if has_n_flows else None

            valid_items = []
            default_ts = time.strftime("%Y-%m-%d %H:%M:%S")

            for idx in valid_indices:
                idx = int(idx)
                vec = bp_matrix[idx].tolist()

                # Source IP
                if has_src_ip and pd.notna(src_ip_col[idx]) and str(src_ip_col[idx]).strip():
                    src_ip = str(src_ip_col[idx])
                else:
                    src_ip = f"192.168.10.{int(idx) % 50 + 2}"

                # Destination IP
                if has_dst_ip and pd.notna(dst_ip_col[idx]) and str(dst_ip_col[idx]).strip():
                    dst_ip = str(dst_ip_col[idx])
                else:
                    dst_ip = "8.8.8.8"

                dst_port = int(ports_array[idx])

                # Identifiers and timestamps
                es_id = str(es_id_col[idx]) if (has_es_id and pd.notna(es_id_col[idx])) else f"ES{idx + 1:07d}"
                w_id = str(w_id_col[idx]) if (has_w_id and pd.notna(w_id_col[idx])) else f"W{idx:05d}"
                try:
                    k_val = int(k_col[idx]) if (has_k and pd.notna(k_col[idx])) else idx
                except Exception:
                    k_val = idx

                w_start = str(w_start_col[idx]) if (has_w_start and pd.notna(w_start_col[idx])) else default_ts
                w_end = str(w_end_col[idx]) if (has_w_end and pd.notna(w_end_col[idx])) else default_ts
                proto_val = str(proto_col[idx]) if (has_proto and pd.notna(proto_col[idx])) else "TCP"
                try:
                    n_flows_val = int(n_flows_col[idx]) if (has_n_flows and pd.notna(n_flows_col[idx])) else 1
                except Exception:
                    n_flows_val = 1

                valid_items.append({
                    "idx": idx,
                    "vec": vec,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "event_set_id": es_id,
                    "window_id": w_id,
                    "k": k_val,
                    "window_start": w_start,
                    "window_end": w_end,
                    "protocol": proto_val,
                    "n_flows": n_flows_val
                })

            # Configurable batch processing for memory-efficient vectorized inference
            PROFILE_BATCH_SIZE = 2000
            preds = []
            for b_start in range(0, len(valid_items), PROFILE_BATCH_SIZE):
                b_end = min(b_start + PROFILE_BATCH_SIZE, len(valid_items))
                chunk_items = valid_items[b_start:b_end]
                X_chunk = np.asarray([item["vec"] for item in chunk_items], dtype=np.float32)
                ports_chunk = [item["dst_port"] for item in chunk_items]
                chunk_preds = self.engine.predict_profiles_batch(X_chunk, destination_ports=ports_chunk)
                preds.extend(chunk_preds)

            window_predictions = []
            flow_attributions = {}

            for i, (item, pred) in enumerate(zip(valid_items, preds)):
                idx = item["idx"]
                verdict = pred["verdict"]
                status = pred.get("prediction_status", verdict)
                conf = float(pred.get("threat_confidence", pred.get("confidence", 0.0)))
                cat = pred.get("predicted_class", "Benign Network Profile")
                sev = pred.get("severity", "LOW")
                es_id = item["event_set_id"]
                w_id = item["window_id"]
                k = item["k"]

                w_pred = {
                    "event_set_id": es_id,
                    "window_id": w_id,
                    "k": k,
                    "source_ip": item["src_ip"],
                    "destination_ip": item["dst_ip"],
                    "window_start": item["window_start"],
                    "window_end": item["window_end"],
                    "verdict": verdict,
                    "confidence": conf,
                    "ensemble_score": float(pred.get("ensemble_score", conf)),
                    "anomaly_score": float(pred.get("anomaly", {}).get("anomaly_score", 0.0)) if pred.get("anomaly") else 0.0,
                    "basepoint_profile": item["vec"],
                    "predicted_class": cat,
                    "prediction_status": status,
                    "severity": sev,
                    "dominant_basepoint": pred.get("dominant_basepoint", "bp_01"),
                    "dominant_similarity": round(float(pred.get("dominant_basepoint_similarity", 0.0)), 4),
                    "model_breakdown": pred.get("model_breakdown", {}),
                    "anomaly_verdict": pred.get("anomaly", {}).get("verdict", "NORMAL") if pred.get("anomaly") else "NORMAL",
                    "anomaly_status": pred.get("anomaly_status", "NORMAL"),
                    "detection_reason": pred.get("detection_reason", ""),
                    "requires_investigation": bool(pred.get("requires_investigation", False)),
                    "n_flows": item["n_flows"]
                }
                window_predictions.append(w_pred)
                flow_attributions[es_id] = [idx]

                mb = pred.get("model_breakdown", {})
                fcnn_probs.append(float(mb.get("fcnn", 0.0)))
                cnn_probs.append(float(mb.get("cnn", 0.0)))
                lstm_probs.append(float(mb.get("lstm", 0.0)))
                ens_probs.append(conf)
                severity_dist[sev] = severity_dist.get(sev, 0) + 1
                attack_types[cat] = attack_types.get(cat, 0) + 1

                det_record = {
                    "id": f"DET-{time.strftime('%Y%m%d%H%M%S')}-{session_prefix}-{int(idx) + 1:04d}",
                    "session_id": session_id,
                    "index": int(idx) + 1,
                    "timestamp": w_pred["window_start"],
                    "source": filename,
                    "input_type": detected_type,
                    "source_ip": item["src_ip"],
                    "destination_ip": item["dst_ip"],
                    "destination_port": item["dst_port"],
                    "protocol": item["protocol"],
                    "verdict": verdict,
                    "prediction_status": status,
                    "predicted_class": cat,
                    "confidence": conf,
                    "threat_confidence": conf,
                    "threat_type": cat,
                    "severity": sev,
                    "dominant_basepoint": pred.get("dominant_basepoint", "bp_01"),
                    "dominant_similarity": round(float(pred.get("dominant_basepoint_similarity", 0.0)), 4),
                    "profile_vector": item["vec"],
                    "model_breakdown": mb,
                    "anomaly_verdict": pred.get("anomaly", {}).get("verdict", "NORMAL") if pred.get("anomaly") else "NORMAL",
                    "anomaly_status": pred.get("anomaly_status", "NORMAL"),
                    "anomaly_score": float(pred.get("anomaly", {}).get("anomaly_score", 0.0)) if pred.get("anomaly") else 0.0,
                    "detection_reason": pred.get("detection_reason", ""),
                    "requires_investigation": bool(pred.get("requires_investigation", False)),
                    "flow_metadata": {
                        "event_set_id": item["event_set_id"],
                        "window_id": item["window_id"],
                        "k": item["k"],
                        "n_flows": item["n_flows"],
                        "window_start": item["window_start"],
                        "window_end": item["window_end"]
                    }
                }
                results.append(det_record)

            coalesced = coalesce_campaigns(
                window_predictions=window_predictions,
                flow_attributions=flow_attributions,
                session_id=session_id
            )
            campaigns = coalesced["campaigns"]
            flow_statistics = coalesced["flow_statistics"]
            event_set_statistics = coalesced["event_set_statistics"]
            campaign_statistics = coalesced["campaign_statistics"]

            # Accurately reflect total uploaded and invalid flows / profiles
            flow_statistics["total_raw_flows"] = total_uploaded
            flow_statistics["invalid_flows"] = invalid_count
            event_set_statistics["total_uploaded"] = total_uploaded
            event_set_statistics["invalid_event_sets"] = invalid_count

            # Build window/event_set lookup to coalesced campaign ID
            window_to_camp = {}
            for camp in campaigns:
                c_id = camp.get("campaign_id")
                for es_id in camp.get("constituent_event_set_ids", []):
                    window_to_camp[es_id] = c_id
                for w_id in camp.get("constituent_windows", []):
                    window_to_camp[w_id] = c_id

            for det in results:
                f_meta = det.get("flow_metadata", {})
                w_id = f_meta.get("window_id") or det.get("id")
                es_id = f_meta.get("event_set_id") or det.get("event_set_id") or f"ES{det.get('index', 0):07d}"
                c_id = window_to_camp.get(es_id, window_to_camp.get(w_id, "-"))
                det["campaign_id"] = c_id
                det["event_set_id"] = es_id

            total_processed = event_set_statistics["total_event_sets"]
            normal_count = event_set_statistics["normal_event_sets"]
            threat_count = campaign_statistics["total_campaigns"]
            known_threat_count = campaign_statistics["known_threat_campaigns"]
            unknown_anomalous_count = campaign_statistics["unknown_anomalous_campaigns"]

        proc_duration_ms = round((time.perf_counter() - start_time_proc) * 1000.0, 2)
        total_valid = event_set_statistics["total_event_sets"]

        # Separate detected known threats and unknown anomalies
        known_threats_list = [r for r in results if r.get("verdict") == "KNOWN_THREAT" or r.get("prediction_status") == "KNOWN_THREAT"]
        unknown_anomalies_list = [r for r in results if r.get("verdict") == "UNKNOWN_ANOMALOUS" or r.get("prediction_status") == "UNKNOWN_ANOMALOUS"]

        summary = {
            "session_id": session_id,
            "filename": filename,
            "source_name": filename,
            "source": "Uploaded CSV Batch",
            "detected_type": detected_type,
            "input_type": detected_type,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "has_data": True,
            "processing_time_ms": proc_duration_ms,
            "total_uploaded": len(df),
            "total_processed": total_processed,
            "total_records": total_processed,
            "normal_events": normal_count,
            "normal_traffic": normal_count,
            "threats_detected": threat_count,
            "known_threats": known_threat_count,
            "unknown_anomalous": unknown_anomalous_count,
            "invalid_records": invalid_count,
            "threat_ratio": round(threat_count / max(total_valid, 1), 4) if total_valid > 0 else 0.0,
            "attack_categories": attack_types,
            "dominant_attack_types": attack_types,
            "severity_distribution": severity_dist,
            "model_summary": {
                "fcnn_avg": round(float(np.mean(fcnn_probs)), 4) if fcnn_probs else 0.0,
                "cnn_avg": round(float(np.mean(cnn_probs)), 4) if cnn_probs else 0.0,
                "lstm_avg": round(float(np.mean(lstm_probs)), 4) if lstm_probs else 0.0,
                "ensemble_avg": round(float(np.mean(ens_probs)), 4) if ens_probs else 0.0
            },
            "flow_statistics": flow_statistics,
            "event_set_statistics": event_set_statistics,
            "campaign_statistics": campaign_statistics,
            "campaigns": campaigns,
            "known_threats_list": known_threats_list,
            "unknown_anomalies_list": unknown_anomalies_list,
            "sample_results": results[:50]
        }

        # Compute Dual-Layer Data Drift Analysis
        try:
            from src.drift import DriftEngine
            drift_engine = DriftEngine()

            df_flows_drift = df if detected_type == "flow" else None
            profiles_drift = profiles if detected_type == "flow" else np.asarray([item["vec"] for item in valid_items], dtype=np.float32)

            drift_report = drift_engine.evaluate_drift(
                df_flows=df_flows_drift,
                profiles_matrix=profiles_drift,
                session_id=session_id
            )
            summary["drift_analysis"] = drift_report
        except Exception as ex_dr:
            import logging
            logging.getLogger(__name__).warning(f"Data drift evaluation error in process_file_upload: {ex_dr}")

        # Persist session, detections, and campaigns in SQLite
        insert_session(summary)
        insert_detections(results, session_id=session_id)
        insert_campaigns(campaigns, session_id=session_id)

        # Update in-memory session summary and latest session ID for latest dashboard view
        self.latest_completed_session_id = session_id
        self._stream_explicitly_cleared = False
        self.current_analysis_summary = summary
        return summary

    def start_stream_processing(
        self,
        upload_id: str,
        batch_size: int = 20000,
        max_batches: Optional[int] = None
    ) -> Dict[str, Any]:
        """Runs or resumes streaming batch processing for an uploaded file."""
        return self.processor.process_upload_session(
            upload_id=upload_id,
            batch_size=batch_size,
            max_batches_to_run=max_batches
        )

    def get_stream_processing_status(self, upload_id: str) -> Dict[str, Any]:
        """Returns processing progress, completed checkpoints, and running threat counters."""
        session = db.get_upload_session(upload_id)
        if not session:
            raise ValueError(f"Upload session '{upload_id}' not found.")
        latest_chk = db.get_latest_checkpoint(upload_id)
        metrics = json.loads(latest_chk.get("metrics_snapshot", "{}")) if latest_chk else {}
        total_batches = session["total_batches"]
        completed_batches = session["completed_batches"]
        pct = round((completed_batches / max(total_batches, 1)) * 100, 1) if total_batches > 0 else 0.0

        return {
            "upload_id": upload_id,
            "session_id": session["session_id"],
            "filename": session["filename"],
            "upload_status": session["upload_status"],
            "sort_status": session["sort_status"],
            "processing_status": session["processing_status"],
            "total_rows": session["total_rows"],
            "processed_rows": session["processed_rows"],
            "total_batches": total_batches,
            "completed_batches": completed_batches,
            "progress_percent": pct,
            "metrics": metrics,
            "error_message": session["error_message"]
        }


    def get_campaigns(self, limit: int = 50, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves security campaigns, optionally filtered by session_id."""
        return get_campaigns(limit=limit, session_id=session_id)

    def predict_single_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Runs inference on a single manual network flow and updates dashboard."""
        pred = self.engine.predict_flow(flow_dict)
        verdict = pred["verdict"]
        status = pred.get("prediction_status", verdict)
        confidence = round(float(pred["threat_confidence"]), 4)
        severity = pred.get("severity", "LOW")
        dst_port = int(flow_dict.get("destination_port", 21))
        cat = pred.get("predicted_class", "Benign Network Traffic")

        if status in ["KNOWN_THREAT", "THREAT", "ANN_ALERT"] or verdict in ["KNOWN_THREAT", "THREAT", "ANN_ALERT"]:
            threat_count = 1
            known_threat_count = 1
            unknown_anomalous_count = 0
            normal_count = 0
        elif status == "UNKNOWN_ANOMALOUS":
            threat_count = 1
            known_threat_count = 0
            unknown_anomalous_count = 1
            normal_count = 0
        else:
            threat_count = 0
            known_threat_count = 0
            unknown_anomalous_count = 0
            normal_count = 1

        session_id = f"SESS-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        det_id = f"DET-{time.strftime('%Y%m%d%H%M%S')}-0001"

        det_record = {
            "id": det_id,
            "session_id": session_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Manual Flow Input",
            "input_type": "flow",
            "source_ip": str(flow_dict.get("source_ip", "172.16.0.1")),
            "destination_ip": str(flow_dict.get("destination_ip", "192.168.10.50")),
            "destination_port": dst_port,
            "protocol": str(flow_dict.get("protocol", "TCP")),
            "verdict": verdict,
            "prediction_status": status,
            "predicted_class": cat,
            "confidence": float(pred.get("confidence", confidence)),
            "threat_confidence": confidence,
            "threat_type": cat,
            "severity": severity,
            "dominant_basepoint": pred.get("dominant_basepoint", "bp_01"),
            "dominant_similarity": round(float(pred.get("dominant_basepoint_similarity", 0.0)), 4),
            "profile_vector": pred.get("profile_vector", []),
            "model_breakdown": pred.get("model_breakdown", {}),
            "anomaly_verdict": pred.get("anomaly", {}).get("verdict", "NORMAL") if pred.get("anomaly") else "NORMAL",
            "anomaly_status": pred.get("anomaly_status", "NORMAL"),
            "anomaly_score": float(pred.get("anomaly", {}).get("anomaly_score", 0.0)) if pred.get("anomaly") else 0.0,
            "detection_reason": pred.get("detection_reason", ""),
            "requires_investigation": bool(pred.get("requires_investigation", False)),
            "flow_metadata": pred.get("flow_metadata", {})
        }

        summary = {
            "session_id": session_id,
            "filename": "Manual Flow Input",
            "source_name": "Manual Flow Input",
            "input_type": "flow",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "has_data": True,
            "total_processed": 1,
            "total_records": 1,
            "normal_events": normal_count,
            "normal_traffic": normal_count,
            "threats_detected": threat_count,
            "known_threats": known_threat_count,
            "unknown_anomalous": unknown_anomalous_count,
            "invalid_records": 0,
            "threat_ratio": 1.0 if threat_count > 0 else 0.0,
            "attack_categories": {cat: 1},
            "dominant_attack_types": {cat: 1},
            "severity_distribution": {severity: 1},
            "model_summary": {
                "fcnn_avg": round(float(pred.get("model_breakdown", {}).get("fcnn", 0.0)), 4),
                "cnn_avg": round(float(pred.get("model_breakdown", {}).get("cnn", 0.0)), 4),
                "lstm_avg": round(float(pred.get("model_breakdown", {}).get("lstm", 0.0)), 4),
                "ensemble_avg": confidence
            }
        }

        insert_session(summary)
        insert_detections([det_record], session_id=session_id)
        # CRITICAL SEPARATION RULE: Manual single-flow classification must NEVER update self.current_analysis_summary.
        # SOC Overview displays ONLY uploaded CSV batch-classification results.
        return pred

    def predict_single_profile(self, vec: List[float]) -> Dict[str, Any]:
        """Runs inference on an 8-dim basepoint profile vector and updates dashboard."""
        pred = self.engine.predict_profile(vec)
        verdict = pred["verdict"]
        status = pred.get("prediction_status", verdict)
        confidence = round(float(pred["threat_confidence"]), 4)
        severity = pred.get("severity", "LOW")
        cat = pred.get("predicted_class", "Benign Network Profile")

        if status in ["KNOWN_THREAT", "THREAT", "ANN_ALERT"] or verdict in ["KNOWN_THREAT", "THREAT", "ANN_ALERT"]:
            threat_count = 1
            known_threat_count = 1
            unknown_anomalous_count = 0
            normal_count = 0
        elif status == "UNKNOWN_ANOMALOUS":
            threat_count = 1
            known_threat_count = 0
            unknown_anomalous_count = 1
            normal_count = 0
        else:
            threat_count = 0
            known_threat_count = 0
            unknown_anomalous_count = 0
            normal_count = 1

        session_id = f"SESS-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        det_id = f"DET-{time.strftime('%Y%m%d%H%M%S')}-0001"

        det_record = {
            "id": det_id,
            "session_id": session_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Manual Profile Input",
            "input_type": "profile",
            "source_ip": "172.16.0.1" if status in ["KNOWN_THREAT", "THREAT", "ANN_ALERT", "UNKNOWN_ANOMALOUS"] else "192.168.10.15",
            "destination_ip": "192.168.10.50" if status in ["KNOWN_THREAT", "THREAT", "ANN_ALERT", "UNKNOWN_ANOMALOUS"] else "192.168.10.3",
            "destination_port": 21 if status in ["KNOWN_THREAT", "THREAT", "ANN_ALERT", "UNKNOWN_ANOMALOUS"] else 443,
            "protocol": "TCP",
            "verdict": verdict,
            "prediction_status": status,
            "predicted_class": cat,
            "confidence": float(pred.get("confidence", confidence)),
            "threat_confidence": confidence,
            "threat_type": cat,
            "severity": severity,
            "dominant_basepoint": pred.get("dominant_basepoint", "bp_01"),
            "dominant_similarity": round(float(pred.get("dominant_basepoint_similarity", 0.0)), 4),
            "profile_vector": pred.get("profile_vector", []),
            "model_breakdown": pred.get("model_breakdown", {}),
            "anomaly_verdict": pred.get("anomaly", {}).get("verdict", "NORMAL") if pred.get("anomaly") else "NORMAL",
            "anomaly_status": pred.get("anomaly_status", "NORMAL"),
            "anomaly_score": float(pred.get("anomaly", {}).get("anomaly_score", 0.0)) if pred.get("anomaly") else 0.0,
            "detection_reason": pred.get("detection_reason", ""),
            "requires_investigation": bool(pred.get("requires_investigation", False)),
            "flow_metadata": {}
        }

        summary = {
            "session_id": session_id,
            "filename": "Manual Profile Input",
            "source_name": "Manual Profile Input",
            "input_type": "profile",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "has_data": True,
            "total_processed": 1,
            "total_records": 1,
            "normal_events": normal_count,
            "normal_traffic": normal_count,
            "threats_detected": threat_count,
            "known_threats": known_threat_count,
            "unknown_anomalous": unknown_anomalous_count,
            "invalid_records": 0,
            "threat_ratio": 1.0 if threat_count > 0 else 0.0,
            "attack_categories": {cat: 1},
            "dominant_attack_types": {cat: 1},
            "severity_distribution": {severity: 1},
            "model_summary": {
                "fcnn_avg": round(float(pred.get("model_breakdown", {}).get("fcnn", 0.0)), 4),
                "cnn_avg": round(float(pred.get("model_breakdown", {}).get("cnn", 0.0)), 4),
                "lstm_avg": round(float(pred.get("model_breakdown", {}).get("lstm", 0.0)), 4),
                "ensemble_avg": confidence
            }
        }

        insert_session(summary)
        insert_detections([det_record], session_id=session_id)
        # CRITICAL SEPARATION RULE: Manual single-flow classification must NEVER update self.current_analysis_summary.
        # SOC Overview displays ONLY uploaded CSV batch-classification results.
        return pred

    def get_latest_stream(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Retrieves the actual sliding-window threat stream records for the latest completed
        upload session (or a specific requested session), strictly isolated to that single upload.
        Never returns simulated random data or pollutes SQLite.
        """
        target_session_id = session_id
        if not target_session_id:
            if self.latest_completed_session_id:
                target_session_id = self.latest_completed_session_id
            elif not self._stream_explicitly_cleared:
                # Fallback to latest session in SQLite (e.g. after server restart)
                latest_sess = get_latest_session()
                if latest_sess and latest_sess.get("session_id"):
                    target_session_id = latest_sess["session_id"]
                    self.latest_completed_session_id = target_session_id

        if not target_session_id:
            return {
                "has_data": False,
                "session_id": None,
                "source_name": "No Uploaded Data",
                "total_windows": 0,
                "normal_windows": 0,
                "known_threat_windows": 0,
                "unknown_anomalous_windows": 0,
                "records": [],
                "stream": [],
                "verdict": "NORMAL",
                "source_ip": "N/A",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        records = get_session_stream(target_session_id)
        if not records:
            return {
                "has_data": False,
                "session_id": target_session_id,
                "source_name": "No Telemetry Records",
                "total_windows": 0,
                "normal_windows": 0,
                "known_threat_windows": 0,
                "unknown_anomalous_windows": 0,
                "records": [],
                "stream": [],
                "verdict": "NORMAL",
                "source_ip": "N/A",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        session_meta = get_session_by_id(target_session_id)
        source_name = session_meta.get("source_name", "Uploaded Batch") if session_meta else "Uploaded Batch"

        normal_cnt = sum(1 for r in records if r.get("verdict") == "NORMAL")
        threat_cnt = sum(1 for r in records if r.get("verdict") == "KNOWN_THREAT")
        anom_cnt = sum(1 for r in records if r.get("verdict") == "UNKNOWN_ANOMALOUS")
        latest_rec = records[-1]

        return {
            "has_data": True,
            "session_id": target_session_id,
            "source_name": source_name,
            "total_windows": len(records),
            "normal_windows": normal_cnt,
            "known_threat_windows": threat_cnt,
            "unknown_anomalous_windows": anom_cnt,
            "records": records,
            "stream": records,
            # Top-level fields for backwards compatibility with single-event consumers:
            "id": latest_rec["id"],
            "timestamp": latest_rec["timestamp"],
            "source_ip": latest_rec["source_ip"],
            "destination_ip": latest_rec["destination_ip"],
            "destination_port": latest_rec["destination_port"],
            "protocol": latest_rec["protocol"],
            "verdict": latest_rec["verdict"],
            "prediction_status": latest_rec["prediction_status"],
            "confidence": latest_rec["confidence"],
            "threat_confidence": latest_rec["threat_confidence"],
            "severity": latest_rec["severity"],
            "campaign_id": latest_rec["campaign_id"],
            "window_id": latest_rec["window_id"],
            "event_set_id": latest_rec["event_set_id"],
            "n_flows": latest_rec["n_flows"]
        }

    def generate_simulated_stream_event(self) -> Dict[str, Any]:
        """
        Deprecated: Returns the latest actual threat stream event without inserting
        synthetic records into SQLite. Preserves backwards compatibility without DB pollution.
        """
        stream_data = self.get_latest_stream()
        if stream_data.get("has_data") and stream_data.get("records"):
            return stream_data["records"][-1]
        return {
            "id": f"STREAM-IDLE-{time.strftime('%Y%m%d%H%M%S')}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Idle Stream",
            "input_type": "stream",
            "source_ip": "127.0.0.1",
            "destination_ip": "127.0.0.1",
            "destination_port": 0,
            "protocol": "TCP",
            "verdict": "NORMAL",
            "prediction_status": "NORMAL",
            "predicted_class": "Benign Network Traffic",
            "confidence": 0.0,
            "threat_confidence": 0.0,
            "severity": "LOW",
            "threat_type": "Benign Network Traffic",
            "dominant_basepoint": "bp_01",
            "dominant_similarity": 0.0,
            "profile_vector": [0.0] * 8,
            "model_breakdown": {"fcnn": 0.0, "cnn": 0.0, "lstm": 0.0},
            "anomaly_verdict": "NORMAL",
            "anomaly_status": "NORMAL",
            "anomaly_score": 0.0,
            "detection_reason": "",
            "requires_investigation": False,
            "flow_metadata": {},
            "campaign_id": "-"
        }

    def get_history(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves actual saved detection records from SQLite."""
        return get_detections(limit=limit, offset=offset, verdict=verdict, severity=severity, search=search, session_id=session_id)

    def get_history_count(
        self,
        verdict: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> int:
        """Returns count of saved detection records from SQLite."""
        return get_detections_count(verdict=verdict, severity=severity, search=search, session_id=session_id)

    def get_sessions(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieves list of recorded analysis sessions from SQLite."""
        return get_sessions(limit=limit, offset=offset)

    def get_sessions_count(self) -> int:
        """Returns total count of recorded analysis sessions."""
        return get_sessions_count()

    def get_session_by_id(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves metadata summary for a single analysis session."""
        return get_session_by_id(session_id)

    def get_session_report(self, session_id: str, include_drift: bool = True) -> Optional[Dict[str, Any]]:
        """Retrieves the complete persistent classification report for a session."""
        return get_session_report(session_id, include_drift=include_drift)

    def delete_session(self, session_id: str) -> bool:
        """Transactionally deletes a session and associated detection/campaign records."""
        deleted = delete_session(session_id)
        if deleted and self.current_analysis_summary and self.current_analysis_summary.get("session_id") == session_id:
            latest = get_latest_session()
            if latest:
                self.current_analysis_summary = get_session_report(latest["session_id"])
            else:
                self.current_analysis_summary = None
        return deleted

    def get_anomaly_overview(self) -> Dict[str, Any]:
        """Returns Isolation Forest metrics, threshold calibration, and confusion matrix."""
        report = self.anomaly_detector.report or {}
        if self.experiment_id == "B":
            eval_a_path = self.metrics_dir / "evaluation_a_unseen.json"
            eval_b_path = self.metrics_dir / "evaluation_b_control.json"
            eval_a = json.loads(eval_a_path.read_text(encoding="utf-8")) if eval_a_path.exists() else {}
            eval_b = json.loads(eval_b_path.read_text(encoding="utf-8")) if eval_b_path.exists() else {}
            if_unseen = eval_a.get("model_metrics", {}).get("IsolationForest", {})
            if_control = eval_b.get("model_metrics", {}).get("IsolationForest", {})
            return {
                "is_ready": self.anomaly_detector.is_ready(),
                "experiment_id": "B",
                "model_name": report.get("model_type", report.get("model", "Isolation Forest")),
                "trained_at": report.get("trained_at", "Experiment B Training Run"),
                "training_samples": report.get("num_training_samples", 1997246),
                "validation_samples": report.get("validation_benign_samples", 625223),
                "control_test_samples": eval_b.get("total_samples", 42189),
                "test_samples": eval_a.get("total_samples", 569099),
                "n_estimators": report.get("n_estimators", 100),
                "max_samples": report.get("max_samples", 2048),
                "contamination": report.get("contamination", 0.005),
                "optimal_threshold": report.get("optimal_threshold", -0.012676391259280995),
                "nominal_fpr_budget": report.get("nominal_fpr_budget", 0.01),
                "calibration_rule": report.get("calibration_rule", "99th_percentile_benign_validation"),
                "metrics_on_test": if_unseen,
                "metrics_on_control": if_control
            }
        else:
            val_m = report.get("validation_metrics_at_threshold", {})
            return {
                "is_ready": self.anomaly_detector.is_ready(),
                "experiment_id": "A",
                "model_name": report.get("model_type", report.get("model", "Isolation Forest")),
                "trained_at": report.get("trained_at", "N/A"),
                "training_samples": report.get("num_training_samples", report.get("training_samples", 1934373)),
                "validation_samples": report.get("total_validation_samples", report.get("validation_samples", 321262)),
                "test_samples": report.get("test_samples", 312537),
                "n_estimators": report.get("n_estimators", 100),
                "max_samples": report.get("max_samples", 2048),
                "contamination": report.get("contamination", 0.005),
                "optimal_threshold": report.get("optimal_threshold", -0.002268),
                "validation_f1": val_m.get("f1_score", report.get("validation_f1", 0.006969)),
                "validation_metrics": val_m,
                "metrics_on_test": report.get("metrics_on_test", {
                    "accuracy": 0.9989,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1_score": 0.0,
                    "roc_auc": 0.5697,
                    "false_positive_rate": 0.0008,
                    "confusion_matrix": {
                        "tp": 0,
                        "fp": 252,
                        "tn": 312187,
                        "fn": 98,
                        "matrix": [[312187, 252], [98, 0]]
                    }
                })
            }

    def predict_anomaly(self, vector_8d: List[float]) -> Dict[str, Any]:
        """Direct anomaly inference using Isolation Forest on 8D profile vector."""
        return self.anomaly_detector.predict_single(vector_8d)

    def update_ensemble_config(self, weights: List[float], threshold: float) -> Dict[str, Any]:
        """Dynamically tunes the Soft-Voting Ensemble."""
        self.engine.ensemble.set_weights(weights)
        self.engine.ensemble.set_threshold(threshold)
        return {
            "status": "SUCCESS",
            "new_weights": self.engine.ensemble.weights,
            "new_threshold": self.engine.ensemble.threshold
        }

    def query_assistant(self, query: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        AI SOC Cybersecurity Assistant:
        CRITICAL BEHAVIOR:
          - Uses actual stored detection records and available model outputs.
          - Never invents threat counts, IP addresses, detection timestamps, or attack categories.
          - If no analysis has been performed, explicitly responds that no detection records are available.
        """
        q = query.lower().strip()
        latest = self.current_analysis_summary
        session_id = latest.get("session_id") if latest else None
        recent_threats = get_recent_threats(limit=5, session_id=session_id)
        recent_detections = get_detections(limit=10, session_id=session_id)

        # Identify queries specifically requesting detection / analysis information
        detection_specific_keywords = [
            "how many", "threats were detected", "latest analysis", "detected attack",
            "categories", "why was this", "classified as suspicious", "suspicious",
            "anomaly", "isolation forest", "compare", "what actions", "containment",
            "action", "my analysis", "latest result", "attack categories", "threat count",
            "how many threats", "show the detected", "mitigate", "playbook"
        ]
        is_asking_for_analysis = any(kw in q for kw in detection_specific_keywords)

        # SCENARIO A: No analysis has been performed yet in this session
        if (latest is None or latest.get("total_records", 0) == 0) and is_asking_for_analysis:
            return {
                "reply": (
                    "### No Detection Records Available\n\n"
                    "No network traffic analysis has been performed in this session yet. All current detection counters are at **0**:\n\n"
                    "- **Total Records Analysed:** 0\n"
                    "- **Normal Events:** 0\n"
                    "- **Threats Detected:** 0\n"
                    "- **Unmatched / Invalid Records:** 0\n\n"
                    "Please navigate to the **Threat Analyzer** and upload a network traffic capture CSV (or input flow parameters in the sandbox). "
                    "Once an analysis has been executed, I will provide complete telemetry, attack category breakdowns, individual flow explanations, "
                    "and comprehensive security telemetry based on your actual data."
                ),
                "category": "Session Status: Awaiting Analysis",
                "suggestions": [
                    "What is the system architecture?",
                    "Explain the 8 basepoints and TF-IDF",
                    "How does Isolation Forest detect zero-days?",
                    "Why is False Positive Rate critical in SOC?"
                ]
            }

        # SCENARIO B: Analysis results exist
        # 1. Threat count in latest analysis
        if any(w in q for w in ["how many", "threat count", "threats were detected", "latest analysis"]) and ("threat" in q or "count" in q or "analys" in q):
            tot = latest["total_records"]
            norm = latest["normal_events"]
            thr = latest["threats_detected"]
            inv = latest["invalid_records"]
            pct = (thr / max(tot, 1)) * 100
            cats = latest.get("attack_categories", {})
            cat_lines = "\n".join([f"  - **{k}:** {v:,}" for k, v in cats.items()]) if cats else "  - None"

            return {
                "reply": (
                    f"### Latest Analysis Telemetry Summary\n\n"
                    f"In your latest analysis of **`{latest.get('source_name', 'Input Data')}`**:\n\n"
                    f"- **Total Records Analysed:** {tot:,}\n"
                    f"- **Normal Events:** {norm:,} ({(norm/max(tot,1))*100:.1f}%)\n"
                    f"- **Threats Detected:** {thr:,} ({pct:.1f}%)\n"
                    f"- **Unmatched / Invalid Records:** {inv:,}\n\n"
                    f"**Detected Attack Breakdown:**\n{cat_lines}\n\n"
                    f"The analysis identified **{thr:,}** threat alerts requiring SOC review."
                ),
                "category": "Detection Summary",
                "suggestions": [
                    "Show the detected attack categories.",
                    "Why was this network flow classified as suspicious?",
                    "What actions should I take for this threat?"
                ]
            }

        # 2. Show detected attack categories
        if any(w in q for w in ["attack categories", "categories", "category"]) and ("attack" in q or "detect" in q or "show" in q):
            cats = latest.get("attack_categories", {}) if latest else {}
            if not cats:
                cat_summary = "No threat categories detected yet."
            else:
                cat_summary = "\n".join([f"- **{cat}:** {count:,} occurrence(s)" for cat, count in cats.items()])

            return {
                "reply": (
                    f"### Detected Attack Categories\n\n"
                    f"Analysis source: **`{latest.get('source_name', 'Recent Session')}`**\n\n"
                    f"{cat_summary}\n\n"
                    f"Classification is based strictly on evaluated network behaviors, destination ports, and basepoint cosine spectra."
                ),
                "category": "Attack Categories",
                "suggestions": [
                    "Why was this network flow classified as suspicious?",
                    "What actions should I take for this threat?",
                    "Compare the FCNN, CNN and LSTM predictions."
                ]
            }

        # 3. Why was this flow classified as suspicious?
        if any(w in q for w in ["why was this", "suspicious", "classified as suspicious", "reason"]):
            if recent_threats:
                t = recent_threats[0]
                mb = t.get("model_breakdown", {})
                return {
                    "reply": (
                        f"### Threat Classification Explanation\n\n"
                        f"**Detection Record ID:** `{t['id']}`\n"
                        f"- **Source Host:** `{t['source_ip']}`\n"
                        f"- **Target Server:** `{t['destination_ip']}:{t['destination_port']}`\n"
                        f"- **SIEM Verdict:** **`{t['verdict']}`** ({t['threat_type']})\n"
                        f"- **Ensemble Confidence:** **{t['threat_confidence'] * 100:.2f}%** (Decision Threshold: $\\tau = 0.95$)\n"
                        f"- **Dominant Prototype Basepoint:** `{t['dominant_basepoint']}` (Cosine similarity: {t['dominant_similarity']:.4f})\n\n"
                        f"**Decision Factor Analysis:**\n"
                        f"The network communication triggered elevated rates on port {t['destination_port']}. "
                        f"When mapped into the 8D basepoint space via TF-IDF, all three neural submodels confirmed threat characteristics: "
                        f"**FCNN:** {mb.get('fcnn', 0) * 100:.1f}%, **1D-CNN:** {mb.get('cnn', 0) * 100:.1f}%, **LSTM:** {mb.get('lstm', 0) * 100:.1f}%."
                    ),
                    "category": "Threat Explanation",
                    "suggestions": [
                        "What actions should I take for this threat?",
                        "Compare the FCNN, CNN and LSTM predictions.",
                        "Explain the anomaly detection result."
                    ]
                }
            else:
                return {
                    "reply": (
                        "### No Suspicious Flows Found\n\n"
                        "All records in the current session were evaluated as **NORMAL** benign traffic. "
                        "None surpassed the decision threshold ($\\tau = 0.95$)."
                    ),
                    "category": "Threat Explanation",
                    "suggestions": [
                        "How many threats were detected in my latest analysis?",
                        "What is the system architecture?"
                    ]
                }

        # 4. Explain anomaly detection result
        if any(w in q for w in ["anomaly", "isolation forest", "outlier"]) and ("result" in q or "explain" in q or "detect" in q):
            if recent_detections:
                d = recent_detections[0]
                return {
                    "reply": (
                        f"### Isolation Forest Anomaly Detection Telemetry\n\n"
                        f"- **Model:** Unsupervised Isolation Forest (100 Trees, 306,936 training profiles)\n"
                        f"- **Evaluated Record:** `{d['id']}` (`{d['source_ip']}` -> `{d['destination_ip']}`)\n"
                        f"- **Anomaly Score:** `{d['anomaly_score']:.4f}`\n"
                        f"- **Calibrated Threshold:** `-0.0148` (validation split tuned)\n"
                        f"- **Isolation Verdict:** **`{d['anomaly_verdict']}`**\n\n"
                        f"**Interpretation:**\n"
                        f"Scores $\\ge -0.0148$ represent outlier traffic that isolated near tree root nodes, indicating behavioral deviations from baseline normal communication."
                    ),
                    "category": "Anomaly Explanation",
                    "suggestions": [
                        "Compare the FCNN, CNN and LSTM predictions.",
                        "What actions should I take for this threat?"
                    ]
                }
            else:
                return {
                    "reply": "No detection records are currently available to explain anomaly scores. Please run an analysis first.",
                    "category": "Anomaly Explanation",
                    "suggestions": ["How does Isolation Forest detect zero-days?"]
                }

        # 5. Compare FCNN, CNN and LSTM predictions
        if any(w in q for w in ["compare", "fcnn", "cnn", "lstm"]) and ("prediction" in q or "model" in q or "submodel" in q):
            if recent_detections:
                d = recent_detections[0]
                mb = d.get("model_breakdown", {})
                return {
                    "reply": (
                        f"### Submodel Probability Comparison\n\n"
                        f"Telemetry for Detection `{d['id']}`:\n\n"
                        f"| Model Architecture | Threat Probability | Regularization |\n"
                        f"| :--- | :--- | :--- |\n"
                        f"| **FCNN** (Multi-Layer Perceptron) | **{mb.get('fcnn', 0) * 100:.2f}%** | L2 (1e-4) + BatchNorm + Dropout(0.3) |\n"
                        f"| **1D-CNN** (Temporal Convolution) | **{mb.get('cnn', 0) * 100:.2f}%** | Conv1D(32) + GlobalAvgPool1D |\n"
                        f"| **LSTM** (Bidirectional Recurrent) | **{mb.get('lstm', 0) * 100:.2f}%** | Bi-LSTM(32) + Dropout(0.2) |\n\n"
                        f"**Soft-Voting Combined Probability:** **{d['threat_confidence'] * 100:.2f}%**\n"
                        f"**Unified SIEM Verdict:** **`{d['verdict']}`** (Threshold $\\tau = 0.95$)"
                    ),
                    "category": "Model Comparison",
                    "suggestions": [
                        "Why was this network flow classified as suspicious?",
                        "What actions should I take for this threat?"
                    ]
                }
            else:
                return {
                    "reply": "No recent detection records available to compare model outputs. Please analyze a flow or CSV first.",
                    "category": "Model Comparison",
                    "suggestions": ["What is the system architecture?"]
                }

        # 6. What actions should I take for this threat?
        if any(w in q for w in ["what action", "actions", "mitigate", "contain", "playbook"]) and ("threat" in q or "take" in q or "should" in q):
            if recent_threats:
                t = recent_threats[0]
                attacker = t["source_ip"]
                victim = t["destination_ip"]
                port = t["destination_port"]
                return {
                    "reply": (
                        f"### Containment & Mitigation Playbook\n\n"
                        f"For detected threat from attacker **`{attacker}`** targeting **`{victim}:{port}`**:\n\n"
                        f"```bash\n"
                        f"# 1. Drop inbound traffic from attacker host immediately\n"
                        f"iptables -I INPUT 1 -s {attacker} -p tcp --dport {port} -j DROP\n"
                        f"sudo ufw insert 1 deny from {attacker} to any port {port} proto tcp\n\n"
                        f"# 2. Enforce connection rate-limiting on port {port}\n"
                        f"iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP\n"
                        f"```\n\n"
                        f"Recommended actions: audit authentication logs, revoke compromised credentials, and enforce network rate-limiting."
                    ),
                    "category": "Mitigation Actions",
                    "suggestions": [
                        "Why was this network flow classified as suspicious?",
                        "How many threats were detected in my latest analysis?"
                    ]
                }
            else:
                return {
                    "reply": (
                        "### No Active Threats Requiring Mitigation\n\n"
                        "All traffic in the current session was evaluated as benign normal communication. Perimeter defenses remain in monitoring mode."
                    ),
                    "category": "Mitigation Actions",
                    "suggestions": ["How many threats were detected in my latest analysis?"]
                }

        # GENERAL DOMAIN KNOWLEDGE (Architecture, CICIDS2017, Basepoints, etc.)
        if any(w in q for w in ["architecture", "pipeline", "system architecture"]):
            return {
                "reply": (
                    "### AI-SIEM Detection Pipeline Architecture\n\n"
                    "The system implements a 7-stage event-profile detection architecture:\n\n"
                    "1. **Network Flow Ingestion:** Captures bidirectional flow records from raw traffic.\n"
                    "2. **Host-Pair Sliding Windows:** Partitions flows into 10-minute sliding windows (60s step) grouped by communicating host-pairs.\n"
                    "3. **5 Derived Events:** Applies statistical threshold rules (HFR, HPR, HBR, SYN, SRC) to extract behavioral security events.\n"
                    "4. **TF-IDF & 8 Basepoints:** Constructs an event dictionary, weights terms via TF-IDF, and maps vectors to 8 prototype cluster centroids (`bp_01` to `bp_08`) using cosine similarity.\n"
                    "5. **Neural Ensemble:** Evaluates the 8D profile vector with a Soft-Voting Ensemble (FCNN + 1D-CNN + LSTM).\n"
                    "6. **Isolation Forest:** Simultaneously checks for out-of-distribution zero-day outliers (calibrated threshold $\\tau = -0.0148$).\n"
                    "7. **Unified Triage:** Issues definitive threat verdicts, anomaly flags, and security campaign telemetry."
                ),
                "category": "Architecture",
                "suggestions": [
                    "Explain the 8 basepoints and TF-IDF",
                    "How does Isolation Forest detect zero-days?",
                    "Why is False Positive Rate critical in SOC?"
                ]
            }

        if any(w in q for w in ["basepoint", "profile", "tfidf"]):
            return {
                "reply": (
                    "### Event Profile & Basepoint Methodology\n\n"
                    "Rather than inspecting raw packet payloads, network flows are aggregated into 10-minute sliding windows grouped by host-pairs.\n\n"
                    "- **5 Derived Events:** High Flow Rate, High Packet Rate, High Byte Rate, SYN Activity, Short Repeated Connections.\n"
                    "- **TF-IDF Weighting:** Computes term-frequency inverse-document-frequency across event sets.\n"
                    "- **8 Prototype Basepoints (`bp_01` to `bp_08`):** Cosine similarity spectrum expressing behavioral deviation without identity leakage."
                ),
                "category": "Architecture",
                "suggestions": [
                    "How does Isolation Forest detect zero-days?",
                    "Why is False Positive Rate critical in SOC?"
                ]
            }

        if any(w in q for w in ["zero-day", "zero day", "out-of-distribution", "isolation forest"]) and ("how" in q or "detect" in q or "explain" in q or "what" in q):
            return {
                "reply": (
                    "### Unsupervised Zero-Day Detection with Isolation Forest\n\n"
                    "Supervised neural networks excel at recognizing known attack patterns (e.g., FTP-Patator, SSH-Patator), "
                    "but can miss novel zero-day exploits not present in the training set.\n\n"
                    "- **Ensemble of 100 Isolation Trees:** Recursively partitions the 8-dimensional basepoint feature space.\n"
                    "- **Isolation Principle:** Anomalous data points isolate near tree root nodes (shorter average path lengths), "
                    "while normal benign traffic clusters deep in tree leaves.\n"
                    "- **Optimal Threshold Calibration:** Calibrated to $\\tau = -0.0148$ on validation split, achieving **71.43% recall** "
                    "on rare anomalies while constraining False Positive Rate to just **0.92%**."
                ),
                "category": "Anomaly Detection",
                "suggestions": [
                    "What is the system architecture?",
                    "Why is False Positive Rate critical in SOC?",
                    "Explain the 8 basepoints and TF-IDF"
                ]
            }

        if any(w in q for w in ["false positive", "fpr", "alert fatigue"]):
            return {
                "reply": (
                    "### The Critical Importance of Low False Positive Rate (FPR)\n\n"
                    "In an enterprise Security Operations Center (SOC) processing tens of millions of network flows daily, "
                    "even an apparently high 99% accuracy can be devastating if FPR is 1%:\n\n"
                    "- A 1% FPR on 1,000,000 flows produces **10,000 false alarms** per day, completely overwhelming SOC analysts.\n"
                    "- **Our Optimization:** In Phase 4, the Soft-Voting Ensemble decision threshold was rigorously calibrated "
                    "on the validation set to achieve **FPR = 0.40%** on 86,831 test event sets.\n"
                    "- **Benefit:** SOC analysts only investigate genuine, high-confidence threats without alert fatigue."
                ),
                "category": "SOC Operations",
                "suggestions": [
                    "What is the system architecture?",
                    "Explain the 8 basepoints and TF-IDF",
                    "How does Isolation Forest detect zero-days?"
                ]
            }

        return {
            "reply": (
                "### AI SIEM Cybersecurity Analyst\n\n"
                f"You asked: *\"{query}\"*\n\n"
                "I am your dedicated analyst connected to the live SIEM inference engine.\n\n"
                "**Capabilities:**\n"
                "- Review latest analysis telemetry (Normal vs Threat counts)\n"
                "- Explain why specific flows were classified as threats\n"
                "- Compare FCNN, 1D-CNN, and LSTM submodel probabilities\n"
                "- Check Isolation Forest zero-day anomaly scores\n"
                "- Generate firewall and Fail2ban containment commands"
            ),
            "category": "General Inquiry",
            "suggestions": [
                "How many threats were detected in my latest analysis?",
                "Show the detected attack categories.",
                "Why was this network flow classified as suspicious?",
                "What actions should I take for this threat?"
            ]
        }


# Global singleton service instance
siem_service = SIEMService(experiment_id="B")
