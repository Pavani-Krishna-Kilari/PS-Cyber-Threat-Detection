"""
Reference Baseline Generator for Dual-Layer Data Drift Detection.
Builds and persists reference statistical baselines for Experiment B:
- Network Features (Layer 1): flow_duration, flow_bytes_s, flow_packets_s, syn_flag_count
- Event Profiles (Layer 2): bp_01 through bp_08 & Dominant Basepoint Distribution

Supports both:
- full_reference: Complete training partition (1,614,510 flows, 1,997,495 event profiles)
- benign_reference: Benign-only training flows (1,353,542 flows) and event profiles (1,997,246 event profiles)
"""

import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT, resolve_path

logger = logging.getLogger(__name__)

DEFAULT_BASELINE_PATH = PROJECT_ROOT / "data" / "reference_baselines" / "drift_reference_exp_b.json"
DATA_DIR = PROJECT_ROOT / "data" / "processed"
EXP_B_DIR = DATA_DIR / "event_profiles_exp_b"

RAW_FEATURES = ["flow_duration", "flow_bytes_s", "flow_packets_s", "syn_flag_count"]
PROFILE_FEATURES = [f"bp_{i:02d}" for i in range(1, 9)]
TUESDAY_CONTROL_BLOCKS = (4, 27)


def extract_distribution_summary(series: pd.Series) -> Dict[str, Any]:
    """
    Extracts summary statistics, deciles (for PSI), and 101 percentiles (for Wasserstein & KS)
    from a continuous feature series.
    """
    cleaned = series.replace([np.inf, -np.inf], np.nan).dropna()
    arr = cleaned.to_numpy(dtype=np.float64)
    if len(arr) == 0:
        return {
            "count": 0,
            "mean": 0.0,
            "std": 0.0,
            "min": 0.0,
            "max": 0.0,
            "q25": 0.0,
            "q75": 0.0,
            "iqr": 1.0,
            "deciles": [0.0] * 11,
            "quantiles_100": [0.0] * 101,
        }

    percentiles_100 = np.linspace(0, 100, 101)
    q_vals = [float(x) for x in np.percentile(arr, percentiles_100)]

    deciles_percentiles = np.linspace(0, 100, 11)
    decile_vals = [float(x) for x in np.percentile(arr, deciles_percentiles)]

    q25 = float(np.percentile(arr, 25))
    q75 = float(np.percentile(arr, 75))
    iqr = float(q75 - q25)
    std = float(np.std(arr))

    return {
        "count": int(len(arr)),
        "mean": float(np.mean(arr)),
        "std": std,
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "q25": q25,
        "q75": q75,
        "iqr": iqr if iqr > 1e-9 else (std if std > 1e-9 else 1.0),
        "deciles": decile_vals,
        "quantiles_100": q_vals,
    }


def compute_dominant_basepoint_distribution(matrix: np.ndarray) -> Dict[str, float]:
    """
    Computes empirical probability distribution of dominant basepoints (bp_01 to bp_08).
    """
    if len(matrix) == 0:
        return {f"bp_{i:02d}": 1.0 / 8.0 for i in range(1, 9)}
    dominant_indices = np.argmax(matrix, axis=1) + 1  # 1 to 8
    counts = pd.Series(dominant_indices).value_counts().reindex(range(1, 9), fill_value=0)
    total = float(len(dominant_indices))
    probs = (counts / total).to_dict()
    return {f"bp_{i:02d}": float(probs.get(i, 0.0)) for i in range(1, 9)}


def build_reference_baseline(output_path: Optional[Path] = None, force: bool = False) -> Dict[str, Any]:
    """
    Builds the reference baseline dictionary from clean training datasets
    and persists it to JSON.
    """
    if output_path is None:
        output_path = DEFAULT_BASELINE_PATH
    output_path = Path(output_path)

    if output_path.exists() and not force:
        logger.info(f"Loading existing reference baseline from {output_path}")
        with open(output_path, "r", encoding="utf-8") as f:
            return json.load(f)

    logger.info("Extracting Experiment B training baseline distributions...")
    t0 = time.time()

    # 1. Layer 1 Raw Network Features
    flow_files = [
        ("Monday-WorkingHours_clean.csv", None),
        ("Tuesday-WorkingHours_clean.csv", TUESDAY_CONTROL_BLOCKS),
        ("Wednesday-workingHours_clean.csv", None),
    ]

    train_flow_chunks = []
    benign_flow_chunks = []

    usecols = ["block_id", "target_binary"] + RAW_FEATURES
    for fname, ctrl_blocks in flow_files:
        fpath = DATA_DIR / fname
        if not fpath.exists():
            raise FileNotFoundError(f"Required clean training flow file not found: {fpath}")

        logger.info(f"Reading training flows from {fname}...")
        df = pd.read_csv(fpath, usecols=usecols)
        if ctrl_blocks is not None:
            mask = ~df["block_id"].isin(ctrl_blocks)
        else:
            mask = np.ones(len(df), dtype=bool)

        df_train = df[mask]
        train_flow_chunks.append(df_train[RAW_FEATURES])
        benign_flow_chunks.append(df_train.loc[df_train["target_binary"] == 0, RAW_FEATURES])
        del df

    df_train_flows = pd.concat(train_flow_chunks, ignore_index=True)
    df_benign_flows = pd.concat(benign_flow_chunks, ignore_index=True)
    del train_flow_chunks, benign_flow_chunks

    net_full = {}
    net_benign = {}
    for feat in RAW_FEATURES:
        net_full[feat] = extract_distribution_summary(df_train_flows[feat])
        net_benign[feat] = extract_distribution_summary(df_benign_flows[feat])

    n_train_flows = len(df_train_flows)
    n_benign_flows = len(df_benign_flows)
    del df_train_flows, df_benign_flows

    # 2. Layer 2 Event Profiles
    ep_path = EXP_B_DIR / "event_profiles.csv"
    et_path = EXP_B_DIR / "event_set_targets.csv"
    if not ep_path.exists() or not et_path.exists():
        raise FileNotFoundError(f"Required event profiles not found in {EXP_B_DIR}")

    logger.info("Reading training event profiles...")
    df_ep = pd.read_csv(ep_path, usecols=["event_set_id", "split"] + PROFILE_FEATURES)
    df_et = pd.read_csv(et_path, usecols=["event_set_id", "split", "target_binary"])

    mask_train_ep = df_ep["split"] == "train"
    df_ep_train = df_ep[mask_train_ep].reset_index(drop=True)
    df_et_train = df_et[df_et["split"] == "train"].reset_index(drop=True)

    mask_benign_ep = df_et_train["target_binary"] == 0
    df_ep_benign = df_ep_train[mask_benign_ep].reset_index(drop=True)

    prof_full = {}
    prof_benign = {}
    for bp in PROFILE_FEATURES:
        prof_full[bp] = extract_distribution_summary(df_ep_train[bp])
        prof_benign[bp] = extract_distribution_summary(df_ep_benign[bp])

    mat_train = df_ep_train[PROFILE_FEATURES].to_numpy(dtype=np.float32)
    mat_benign = df_ep_benign[PROFILE_FEATURES].to_numpy(dtype=np.float32)

    dom_full = compute_dominant_basepoint_distribution(mat_train)
    dom_benign = compute_dominant_basepoint_distribution(mat_benign)

    n_train_profiles = len(df_ep_train)
    n_benign_profiles = len(df_ep_benign)
    del df_ep, df_et, df_ep_train, df_et_train, df_ep_benign, mat_train, mat_benign

    baseline_data = {
        "experiment": "exp_b",
        "created_at": datetime.now().isoformat(),
        "n_training_flows": n_train_flows,
        "n_benign_training_flows": n_benign_flows,
        "n_training_profiles": n_train_profiles,
        "n_benign_training_profiles": n_benign_profiles,
        "raw_features": RAW_FEATURES,
        "profile_features": PROFILE_FEATURES,
        "full_reference": {
            "network_features": net_full,
            "event_profiles": prof_full,
            "dominant_basepoint_distribution": dom_full,
        },
        "benign_reference": {
            "network_features": net_benign,
            "event_profiles": prof_benign,
            "dominant_basepoint_distribution": dom_benign,
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)

    elapsed = time.time() - t0
    logger.info(f"Reference baseline saved to {output_path} in {elapsed:.2f}s")
    return baseline_data


def load_reference_baseline(baseline_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads precalculated reference baseline. If missing, builds it automatically.
    """
    if baseline_path is None:
        baseline_path = DEFAULT_BASELINE_PATH
    baseline_path = Path(baseline_path)
    if not baseline_path.exists():
        logger.warning(f"Baseline file {baseline_path} does not exist. Building now...")
        return build_reference_baseline(output_path=baseline_path)

    with open(baseline_path, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    baseline = build_reference_baseline(force=True)
    print(f"\nSuccessfully generated baseline with {baseline['n_training_flows']} flows and {baseline['n_training_profiles']} profiles.")
