"""
Stage 1: Production-Grade Runtime Raw-Flow Event Aggregator
===========================================================
Implements strictly research-aligned, leakage-free sliding-window event aggregation
for the active Experiment B SIEM pipeline.

Methodological Guarantees:
  1. Directional (source_ip, destination_ip) communication grouping.
  2. Whole-minute timeline anchor: t0 = timestamps.min().floor('min').
  3. 60-second time bins and 600-second (10-bin) sliding windows with 60s step.
  4. Half-open window intervals: [start_bin, end_bin) where end_bin = start_bin + 10.
  5. Strict window acceptance: requires n_bins >= 10 (at least 10 occupied 60s bins).
  6. Exact Experiment B thresholds, sublinear TF-IDF, and 8D basepoint cosine projection.
  7. Strict separation between Operational Ingestion and Benchmark Replay.
  8. Zero leakage: labels, ports, protocol, and IPs are NEVER model features.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT
from src.event_profiles.windows import compute_bins, bin_split_names, valid_windows, aggregate_to_windows
from src.event_profiles.events import (
    EVENT_NAMES, FLOW_EVENT_SPECS, compare, apply_flow_events
)
from src.event_profiles.tfidf import transform
from src.event_profiles.basepoints import compute_profiles


# Required columns in an uploaded raw network-flow CSV
REQUIRED_FLOW_COLUMNS = {
    "source_ip",
    "destination_ip",
    "flow_duration",
    "flow_packets_s",
    "flow_bytes_s",
    "syn_flag_count",
    "timestamp"
}

# Forbidden columns that must NEVER be fed to model feature generation
FORBIDDEN_COLUMNS = {
    "label", "label_original", "target_binary", "target_multiclass", "attack_type",
    "actual_label", "threat_type"
}

# Supported partition names for benchmark replay
VALID_BENCHMARK_SPLITS = {"train", "validation", "test", "control_test"}


class AggregatorError(Exception):
    """Base exception for all raw-flow aggregation errors."""
    pass


class InsufficientTemporalSpanError(AggregatorError):
    """Raised when the input dataset does not occupy at least 10 time bins (600s window)."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class InvalidTimestampError(AggregatorError):
    """Raised when timestamps are missing, null, or exceed maximum unparseable fraction."""
    pass


class MissingFeatureColumnsError(AggregatorError):
    """Raised when required flow feature columns are absent."""
    pass


class InvalidBenchmarkAnnotationError(AggregatorError):
    """Raised when benchmark replay block_id or split annotations fail arithmetic or purity checks."""
    pass


class RawFlowAggregator:
    """
    Production-grade runtime aggregator converting raw network-flow streams
    into leakage-safe, 8-dimensional event profiles ('bp_01' through 'bp_08').
    """

    def __init__(
        self,
        experiment_id: str = "B",
        data_dir: Optional[Path] = None,
        step_seconds: int = 60,
        window_size_seconds: int = 600,
        block_minutes: int = 20
    ):
        self.experiment_id = experiment_id
        if data_dir is not None:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = (PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_b") if experiment_id == "B" else (PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_a")

        self.step_seconds = int(step_seconds)
        self.window_size_seconds = int(window_size_seconds)
        self.window_bins = self.window_size_seconds // self.step_seconds  # W = 10
        self.block_minutes = int(block_minutes)

        self.thresholds: Optional[Dict[str, Any]] = None
        self.tfidf_model: Optional[Dict[str, Any]] = None
        self.basepoints: Optional[np.ndarray] = None
        self.basepoint_names: List[str] = []

        self._load_experiment_artifacts()

    def _load_experiment_artifacts(self):
        """Loads verified, frozen Experiment B training artifacts."""
        thresh_path = self.data_dir / "event_thresholds.json"
        tfidf_path = self.data_dir / "tfidf_model.json"
        bp_path = self.data_dir / "basepoints.csv"

        if not thresh_path.exists():
            raise FileNotFoundError(f"Missing event_thresholds.json in {self.data_dir}")
        if not tfidf_path.exists():
            raise FileNotFoundError(f"Missing tfidf_model.json in {self.data_dir}")
        if not bp_path.exists():
            raise FileNotFoundError(f"Missing basepoints.csv in {self.data_dir}")

        self.thresholds = json.loads(thresh_path.read_text(encoding="utf-8"))
        self.tfidf_model = json.loads(tfidf_path.read_text(encoding="utf-8"))

        df_bp = pd.read_csv(bp_path)
        self.basepoints = df_bp[EVENT_NAMES].to_numpy(dtype=np.float64)
        self.basepoint_names = [f"bp_{i:02d}" for i in range(1, len(self.basepoints) + 1)]

    def validate_schema(self, df: pd.DataFrame) -> Tuple[bool, str]:
        """
        Validates column schema, identifying whether the input is:
          - 'RAW_FLOW': Network-flow records requiring window aggregation
          - 'EVENT_PROFILE': Preaggregated 8-dimensional profile CSV
          - 'UNSUPPORTED': Missing required attributes
        """
        cols = set(df.columns)
        bp_cols = {f"bp_{i:02d}" for i in range(1, 9)}
        if bp_cols.issubset(cols):
            return True, "EVENT_PROFILE"

        missing = REQUIRED_FLOW_COLUMNS - cols
        if not missing:
            return True, "RAW_FLOW"

        return False, f"Missing required flow columns: {sorted(list(missing))}"

    def parse_and_sort_flows(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validates timestamps, removes forbidden columns, and applies deterministic sorting.
        """
        is_valid, mode = self.validate_schema(df)
        if not is_valid:
            raise MissingFeatureColumnsError(mode)

        flows = df.copy()

        # Deterministic source row preservation
        if "source_row" not in flows.columns:
            flows["source_row"] = np.arange(len(flows), dtype="int64")

        # Parse timestamps strictly
        try:
            flows["timestamp"] = pd.to_datetime(flows["timestamp"], errors="coerce")
        except Exception as e:
            raise InvalidTimestampError(f"Failed to parse timestamp column: {e}")

        unparseable = flows["timestamp"].isna().sum()
        if unparseable > 0:
            unparseable_fraction = unparseable / len(flows)
            if unparseable_fraction > 0.001 or unparseable == len(flows):
                raise InvalidTimestampError(
                    f"{unparseable:,} rows ({unparseable_fraction:.2%}) have unparseable timestamps. Maximum allowed is 0.1%."
                )
            # Drop rare unparseable rows safely
            flows = flows.dropna(subset=["timestamp"]).reset_index(drop=True)

        # Ensure numeric columns are strictly cast and finite
        numeric_cols = ["flow_duration", "flow_packets_s", "flow_bytes_s", "syn_flag_count"]
        for c in numeric_cols:
            flows[c] = pd.to_numeric(flows[c], errors="coerce").fillna(0.0)

        # Deterministic sorting matching offline pipeline: timestamp then source_row
        flows = flows.sort_values(["timestamp", "source_row"], kind="stable").reset_index(drop=True)
        return flows

    def aggregate_flows(
        self,
        df: pd.DataFrame,
        is_benchmark_replay: bool = False,
        capture_day: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes sliding-window event aggregation on raw flow records.

        Parameters:
            df: DataFrame containing raw network flows.
            is_benchmark_replay: If True, enforces strict Experiment B 20-minute block splits.
            capture_day: Optional capture weekday string (e.g. 'Tuesday', 'Friday') for replay.

        Returns:
            Dict containing:
              - 'profiles': np.ndarray of shape (N_sets, 8) with bp_01 through bp_08
              - 'profile_df': pd.DataFrame with metadata IDs and 8D basepoint columns
              - 'event_sets': pd.DataFrame with raw event counts and flow statistics
              - 'flow_attributions': Dict[event_set_id, List[int]] mapping set to flow rows
              - 'metadata': Dict with summary metrics
        """
        flows = self.parse_and_sort_flows(df)
        n_flows = len(flows)

        # 1. Timeline anchoring: t0 = timestamps.min().floor('min')
        bins, t0 = compute_bins(flows["timestamp"], self.step_seconds)
        max_bin = int(bins.max()) if len(bins) > 0 else -1
        n_bins = max_bin + 1

        # 2. Strict Full-Window Acceptance Check
        if n_bins < self.window_bins:
            elapsed_sec = float((flows["timestamp"].max() - flows["timestamp"].min()).total_seconds()) if n_flows > 0 else 0.0
            raise InsufficientTemporalSpanError(
                f"Raw-flow event aggregation requires at least one complete 600-second window ({self.window_bins} bins). "
                f"Provided dataset occupies {n_bins} time bin(s) (elapsed: {elapsed_sec:.2f}s, maximum bin index: {max_bin}).",
                details={
                    "n_bins": n_bins,
                    "max_bin": max_bin,
                    "bins_required": self.window_bins,
                    "elapsed_seconds": elapsed_sec,
                    "window_size_seconds": self.window_size_seconds,
                    "step_seconds": self.step_seconds
                }
            )

        # 3. Partition / Split assignment
        if is_benchmark_replay or ("split" in flows.columns or "block_id" in flows.columns):
            # Benchmark Replay Mode: Validate and enforce 20-minute split blocks
            names = self._validate_and_build_split_names(flows, bins, n_bins, capture_day)
        else:
            # Operational Capture Mode: Continuous operational monitoring stream
            names = np.array(["operational"] * n_bins, dtype=object)

        # 4. Determine valid windows
        valid, window_split = valid_windows(names, self.window_bins)
        n_windows = len(valid)

        if not np.any(valid):
            raise AggregatorError(
                f"No valid sliding windows could be constructed. Data spanned {n_bins} bins, but all candidate windows were invalidated."
            )

        # 5. Directional Communication Grouping: (source_ip, destination_ip)
        pair_series = flows.groupby(["source_ip", "destination_ip"], sort=False).ngroup()
        pair_idx = pair_series.to_numpy(dtype="int64")

        # Map pair integer back to IP strings
        unique_pairs_df = flows.assign(pair=pair_idx).drop_duplicates("pair")[["pair", "source_ip", "destination_ip"]]
        pair_to_ips = dict(zip(unique_pairs_df["pair"], zip(unique_pairs_df["source_ip"], unique_pairs_df["destination_ip"])))

        # 6. Apply flow-level event rules using frozen thresholds
        flow_flags = apply_flow_events(flows, self.thresholds)
        # Stacking [1, flag0, flag1, flag2, flag3] for aggregate_to_windows summation
        flow_values = np.column_stack([np.ones(n_flows, dtype="int64"), flow_flags.astype("int64")])

        # 7. Aggregate flows into sliding windows
        agg = aggregate_to_windows(pair_idx, bins, flow_values, self.window_bins, valid, n_windows)
        agg = agg.sort_values(["k", "pair"], kind="stable").reset_index(drop=True)

        if agg.empty:
            raise AggregatorError("Event aggregation produced zero event sets from valid windows.")

        # 8. Construct Event Sets DataFrame
        cap_sets = pd.DataFrame({
            "pair": agg["pair"].to_numpy(dtype="int64"),
            "k": agg["k"].to_numpy(dtype="int64"),
            "n_flows": agg["v0"].to_numpy(dtype="int64")
        })
        for j, (name, _, _) in enumerate(FLOW_EVENT_SPECS, start=1):
            cap_sets[name] = agg[f"v{j}"].to_numpy(dtype="int64")

        cap_sets["split"] = window_split[cap_sets["k"].to_numpy()]

        # Compute half-open window boundaries: [window_start, window_end)
        cap_sets["window_start"] = t0 + pd.to_timedelta(cap_sets["k"].to_numpy() * self.step_seconds, unit="s")
        cap_sets["window_end"] = cap_sets["window_start"] + pd.Timedelta(seconds=self.window_size_seconds)

        # Assign identifiers
        n_sets = len(cap_sets)
        cap_sets["event_set_id"] = [f"ES{str(i + 1).zfill(7)}" for i in range(n_sets)]
        cap_sets["window_id"] = [f"W{str(k).zfill(5)}" for k in cap_sets["k"]]

        # Map IP endpoints
        ips = [pair_to_ips[p] for p in cap_sets["pair"]]
        cap_sets["source_ip"] = [ip[0] for ip in ips]
        cap_sets["destination_ip"] = [ip[1] for ip in ips]

        # 9. Evaluate Set-Level Event: HIGH_FLOW_RATE
        # Exact Experiment B threshold: strictly greater than 12.0 flows in set
        hfr_thresh = self.thresholds["HIGH_FLOW_RATE"]["threshold"]  # 12.0
        hfr_comp = self.thresholds["HIGH_FLOW_RATE"]["comparison"]   # 'gt'
        hfr = compare(cap_sets["n_flows"].to_numpy(dtype="float64"), hfr_thresh, hfr_comp).astype("int64")
        cap_sets["HIGH_FLOW_RATE"] = hfr

        # 10. Extract Counts Matrix in Authoritative EVENT_NAMES Order
        counts_matrix = cap_sets[EVENT_NAMES].to_numpy(dtype="int64")

        # 11. Transform Event Sets with Pre-Calibrated TF-IDF Model
        tfidf_vectors = transform(counts_matrix, self.tfidf_model)

        # 12. Compute 8-Dimensional Cosine Similarity Profiles
        profiles = compute_profiles(tfidf_vectors, self.basepoints)

        # 13. Map Flow Row Attributions to Event Sets
        # Maps each event set to the original flow indices contained in [k, k + W)
        flow_attributions = self._map_flow_indices_to_event_sets(
            flows=flows,
            pair_idx=pair_idx,
            bins=bins,
            cap_sets=cap_sets
        )

        # 14. Assemble Output DataFrames
        id_cols = ["event_set_id", "window_id", "source_ip", "destination_ip", "window_start", "window_end", "n_flows"]
        profile_df = pd.concat([
            cap_sets[id_cols].copy(),
            pd.DataFrame(profiles, columns=self.basepoint_names)
        ], axis=1)

        summary_meta = {
            "experiment_id": self.experiment_id,
            "total_raw_flows": n_flows,
            "total_bins": n_bins,
            "total_event_sets": n_sets,
            "unique_pairs": len(unique_pairs_df),
            "window_size_seconds": self.window_size_seconds,
            "step_seconds": self.step_seconds,
            "window_bins": self.window_bins,
            "t0": t0.isoformat(),
            "is_benchmark_replay": bool(is_benchmark_replay)
        }

        return {
            "profiles": profiles,
            "profile_df": profile_df,
            "event_sets": cap_sets,
            "flow_attributions": flow_attributions,
            "metadata": summary_meta
        }

    def _map_flow_indices_to_event_sets(
        self,
        flows: pd.DataFrame,
        pair_idx: np.ndarray,
        bins: np.ndarray,
        cap_sets: pd.DataFrame
    ) -> Dict[str, List[int]]:
        """
        Maps each (pair, k) event set to its constituent flow row indices.
        A flow belongs to window k if flow.pair == k.pair and k <= flow.bin < k + W.
        """
        flow_df = pd.DataFrame({
            "flow_idx": np.arange(len(flows), dtype="int64"),
            "pair": pair_idx,
            "bin": bins
        })

        # Group flows by (pair, bin)
        bin_groups = flow_df.groupby(["pair", "bin"])["flow_idx"].apply(list).to_dict()

        flow_map: Dict[str, List[int]] = {}
        W = self.window_bins
        for _, row in cap_sets[["event_set_id", "pair", "k"]].iterrows():
            es_id = row["event_set_id"]
            p = row["pair"]
            k_start = row["k"]
            members: List[int] = []
            for b in range(k_start, k_start + W):
                sub = bin_groups.get((p, b))
                if sub:
                    members.extend(sub)
            flow_map[es_id] = members

        return flow_map

    def _validate_and_build_split_names(
        self,
        flows: pd.DataFrame,
        bins: np.ndarray,
        n_bins: int,
        capture_day: Optional[str]
    ) -> np.ndarray:
        """
        Validates benchmark annotations against Experiment B 20-minute block boundaries.
        """
        block_sec = self.block_minutes * 60
        bins_per_block = block_sec // self.step_seconds  # 20 bins per block

        # Check block_id
        if "block_id" in flows.columns:
            try:
                block_ids = flows["block_id"].to_numpy(dtype="int64")
            except (ValueError, TypeError) as e:
                raise InvalidBenchmarkAnnotationError(f"Invalid non-integer block_id column: {e}")

            # Arithmetic consistency check: bins // bins_per_block == block_id
            mismatches = int((bins // bins_per_block != block_ids).sum())
            if mismatches > 0:
                raise InvalidBenchmarkAnnotationError(
                    f"{mismatches:,} flows have a block_id that disagrees with timestamp block arithmetic (block length {self.block_minutes} min)."
                )
        else:
            # Derive arithmetic block_id
            block_ids = bins // bins_per_block

        # Check split
        if "split" in flows.columns:
            split_series = flows["split"].astype(str)
            invalid_splits = set(split_series) - VALID_BENCHMARK_SPLITS
            if invalid_splits:
                raise InvalidBenchmarkAnnotationError(f"Disallowed split values in benchmark replay: {invalid_splits}")

            # Verify block purity: each block_id must map to exactly one split
            pairs = pd.DataFrame({"b": block_ids, "s": split_series}).drop_duplicates()
            if pairs["b"].duplicated().any():
                raise InvalidBenchmarkAnnotationError("Contradictory split annotations: a single block contains multiple split values.")

            mapping = dict(zip(pairs["b"].tolist(), pairs["s"].tolist()))
            bin_block = np.arange(n_bins) // bins_per_block
            return np.array([mapping.get(int(b), "unknown") for b in bin_block], dtype=object)
        else:
            # Derive Experiment B split from capture day and block_id
            day_str = (capture_day or "").lower()
            bin_block = np.arange(n_bins) // bins_per_block
            split_list = []
            for b in bin_block:
                if "tuesday" in day_str:
                    split_list.append("control_test" if int(b) in (4, 27) else "train")
                elif any(d in day_str for d in ["monday", "wednesday"]):
                    split_list.append("train")
                elif "thursday" in day_str:
                    split_list.append("validation")
                elif "friday" in day_str:
                    split_list.append("test")
                else:
                    split_list.append("test")
            return np.array(split_list, dtype=object)
