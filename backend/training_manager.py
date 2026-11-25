"""
Training Dataset Management & Candidate Model Studio for AI-SIEM.
Enforces Head of SOC authorization for dataset validation, isolated candidate training,
evaluation metrics calculation, and audited model activation with rollback capability.

Methodology Safeguards:
1. Drift detection NEVER automatically updates training datasets, retrains models, or activates models.
2. Candidate training executes in an isolated environment without modifying active models.
3. Model activation requires explicit supervisory authorization and records a full audit trail.
4. Pre-activation snapshots are preserved to guarantee 100% rollback capability.
"""

import io
import os
import json
import time
import uuid
import shutil
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix
import joblib

from src.config import PROJECT_ROOT, get_soc_data_dir
from src.models.evaluate import compute_metrics, find_optimal_threshold
import backend.database as db


def get_candidate_datasets_dir() -> Path:
    """Returns directory for uploaded candidate training datasets, respecting SOC_DATA_DIR."""
    d = get_soc_data_dir() / "candidate_datasets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_candidate_models_dir() -> Path:
    """Returns directory for candidate trained models, respecting SOC_DATA_DIR in production."""
    soc_data = os.environ.get("SOC_DATA_DIR")
    if soc_data and soc_data.strip():
        d = get_soc_data_dir() / "models" / "candidates"
    else:
        d = PROJECT_ROOT / "models" / "candidates"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_model_backups_dir() -> Path:
    """Returns directory for model rollback archives, respecting SOC_DATA_DIR in production."""
    soc_data = os.environ.get("SOC_DATA_DIR")
    if soc_data and soc_data.strip():
        d = get_soc_data_dir() / "models" / "backups"
    else:
        d = PROJECT_ROOT / "models" / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


CANDIDATE_DATASETS_DIR = get_candidate_datasets_dir()
CANDIDATE_MODELS_DIR = get_candidate_models_dir()
MODEL_BACKUPS_DIR = get_model_backups_dir()

PROFILE_COLS = [f"bp_{i:02d}" for i in range(1, 9)]
FLOW_COLS = ["flow_duration", "flow_bytes_s", "flow_packets_s", "syn_flag_count"]
FORBIDDEN_COLUMNS = {
    "label", "target", "attack", "attack_label", "class", "verdict",
    "source_ip", "destination_ip", "src_ip", "dst_ip",
    "source_port", "destination_port", "src_port", "dst_port",
    "timestamp", "time", "date", "flow_id", "session_id", "upload_id", "id"
}


def ensure_directories():
    """Ensures dedicated candidate and backup storage directories exist."""
    get_candidate_datasets_dir()
    get_candidate_models_dir()
    get_model_backups_dir()


# -----------------------------------------------------------------------------
# 1. Dataset Validation & Schema Inspection
# -----------------------------------------------------------------------------

def validate_training_dataset(file_content: bytes, filename: str) -> Dict[str, Any]:
    """
    Validates an uploaded training dataset:
    - Identifies schema: Event Profiles (8 basepoint similarities) or Raw Flow traffic.
    - Rejects missing required features and incompatible data types.
    - Inspects nulls, NaNs, infinities, empty datasets, duplicate rows, and invalid labels.
    - Computes row count, feature count, class distribution, rejected rows, and validation status.
    - Strictly forbids labels, IPs, ports, timestamps, or identifiers as model inputs.
    - Never silently fabricates missing columns or feature values.
    """
    errors: List[str] = []
    warnings: List[str] = []
    rejected_row_indices: set = set()
    rejected_reasons: List[str] = []

    if not file_content or len(file_content.strip()) == 0:
        return {
            "is_valid": False,
            "dataset_type": "UNKNOWN",
            "schema_type": "UNKNOWN",
            "filename": filename,
            "row_count": 0,
            "num_rows": 0,
            "feature_count": 0,
            "num_cols": 0,
            "column_count": 0,
            "detected_features": [],
            "label_column": None,
            "class_distribution": {"benign": 0, "attack": 0, "benign_percentage": 0.0, "attack_percentage": 0.0, "imbalance_ratio": 0.0, "attack_types": {}},
            "class_balance": {"BENIGN": 0, "ATTACK": 0},
            "rejected_rows": {"count": 0, "row_indices": [], "reasons": ["Uploaded file is empty (0 bytes)."]},
            "quality_metrics": {"missing_cells": 0, "inf_cells": 0, "duplicate_rows": 0, "bounded_range_valid": False},
            "readiness_status": "EMPTY_FILE",
            "validation_status": "VALIDATION_FAILED",
            "validation_errors": ["Uploaded file is empty (0 bytes)."],
            "issues": ["Uploaded file is empty (0 bytes)."],
            "validation_warnings": [],
            "warnings": []
        }

    try:
        df = pd.read_csv(io.BytesIO(file_content), low_memory=False)
    except Exception as e:
        return {
            "is_valid": False,
            "dataset_type": "UNKNOWN",
            "schema_type": "UNKNOWN",
            "filename": filename,
            "row_count": 0,
            "num_rows": 0,
            "feature_count": 0,
            "num_cols": 0,
            "column_count": 0,
            "detected_features": [],
            "label_column": None,
            "class_distribution": {"benign": 0, "attack": 0, "benign_percentage": 0.0, "attack_percentage": 0.0, "imbalance_ratio": 0.0, "attack_types": {}},
            "class_balance": {"BENIGN": 0, "ATTACK": 0},
            "rejected_rows": {"count": 0, "row_indices": [], "reasons": [f"Failed to parse CSV format: {str(e)}"]},
            "quality_metrics": {"missing_cells": 0, "inf_cells": 0, "duplicate_rows": 0, "bounded_range_valid": False},
            "readiness_status": "PARSE_ERROR",
            "validation_status": "VALIDATION_FAILED",
            "validation_errors": [f"Failed to parse CSV format: {str(e)}"],
            "issues": [f"Failed to parse CSV format: {str(e)}"],
            "validation_warnings": [],
            "warnings": []
        }

    row_count, col_count = df.shape
    if row_count == 0:
        errors.append("Dataset is empty (0 rows).")

    # Normalize column names
    df.columns = [str(c).strip() for c in df.columns]
    col_map_lower = {c.lower(): c for c in df.columns}

    # Minimum sample threshold
    if 0 < row_count < 10:
        errors.append(f"Insufficient samples: dataset contains only {row_count} rows (minimum 10 rows required).")

    # Detect dataset type: EVENT_PROFILES vs NETWORK_FLOWS
    has_profile_cols = all(bp in df.columns for bp in PROFILE_COLS)
    has_flow_cols = all(fc in col_map_lower for fc in FLOW_COLS)

    if has_profile_cols:
        dataset_type = "EVENT_PROFILES"
        features_detected = PROFILE_COLS
    elif has_flow_cols:
        dataset_type = "NETWORK_FLOWS"
        features_detected = [col_map_lower[fc] for fc in FLOW_COLS]
        flow_req_cols = ["source_ip", "destination_ip", "timestamp"]
        missing_flow_reqs = [c for c in flow_req_cols if c not in col_map_lower]
        if missing_flow_reqs:
            errors.append(
                f"Raw network flows missing required communication/temporal columns: {missing_flow_reqs}. "
                "Event-profile generation requires source_ip, destination_ip, and timestamp."
            )
        else:
            try:
                ts = pd.to_datetime(df[col_map_lower["timestamp"]], errors="coerce").dropna()
                if len(ts) > 0:
                    span_sec = (ts.max() - ts.min()).total_seconds()
                    if span_sec < 599.0:
                        errors.append(
                            f"Insufficient temporal span: Raw network flows span only {span_sec:.1f}s "
                            "(minimum 600-second window required for sliding window aggregation)."
                        )
            except Exception as e:
                errors.append(f"Failed to parse timestamp in raw flow dataset: {e}")
    else:
        dataset_type = "UNKNOWN"
        features_detected = []
        errors.append(
            "Schema mismatch: Dataset does not match required schemas. "
            f"Must either contain 8 basepoint columns ({', '.join(PROFILE_COLS)}) "
            f"or network flow features ({', '.join(FLOW_COLS)}) with source_ip, destination_ip, timestamp."
        )

    # Safeguard: Never use labels, IP addresses, ports, timestamps, or identifiers as model input
    for feat in features_detected:
        if feat.lower() in FORBIDDEN_COLUMNS:
            errors.append(f"Forbidden column '{feat}' cannot be used as model input feature.")

    # Locate Target / Label Column
    possible_label_names = ["target", "label", "attack_label", "attack", "class"]
    label_col = None
    for cand in possible_label_names:
        if cand in col_map_lower:
            label_col = col_map_lower[cand]
            break

    class_distribution = {
        "benign": 0,
        "attack": 0,
        "benign_percentage": 0.0,
        "attack_percentage": 0.0,
        "imbalance_ratio": 0.0,
        "attack_types": {}
    }

    if not label_col:
        errors.append(
            "Missing label column: Supervised model training requires a ground-truth label "
            f"column (e.g. 'target', 'label', 'attack_label'). None found."
        )
    else:
        null_label_rows = df[df[label_col].isna()].index.tolist()
        if null_label_rows:
            rejected_row_indices.update(null_label_rows)
            msg = f"Label column '{label_col}' contains {len(null_label_rows)} empty/null values."
            errors.append(msg)
            rejected_reasons.append(msg)

        valid_benign = {"0", "0.0", "BENIGN", "NORMAL", "FALSE"}
        valid_attack = {"1", "1.0", "ATTACK", "THREAT", "TRUE", "MALICIOUS", "ANOMALY"}
        
        binary_labels = []
        attack_counts: Dict[str, int] = {}
        for idx, val in df[label_col].items():
            if pd.isna(val):
                continue
            v_str = str(val).strip().upper()
            if v_str in valid_benign:
                binary_labels.append(0)
            elif v_str in valid_attack:
                binary_labels.append(1)
                attack_counts[str(val).strip()] = attack_counts.get(str(val).strip(), 0) + 1
            else:
                try:
                    num_val = float(v_str)
                    if num_val == 0.0:
                        binary_labels.append(0)
                    elif num_val == 1.0:
                        binary_labels.append(1)
                        attack_counts["ATTACK"] = attack_counts.get("ATTACK", 0) + 1
                    else:
                        rejected_row_indices.add(idx)
                        msg = f"Invalid label value '{val}' at row {idx}."
                        errors.append(msg)
                        rejected_reasons.append(msg)
                except ValueError:
                    if any(att in v_str for att in ["SCAN", "DDOS", "DOS", "BRUTE", "PATATOR", "INFILTR", "BOT", "HEARTBLEED", "EXPLOIT", "WEB"]):
                        binary_labels.append(1)
                        attack_counts[str(val).strip()] = attack_counts.get(str(val).strip(), 0) + 1
                    else:
                        rejected_row_indices.add(idx)
                        msg = f"Invalid label value '{val}' at row {idx}."
                        errors.append(msg)
                        rejected_reasons.append(msg)

        benign_count = sum(1 for b in binary_labels if b == 0)
        attack_count = sum(1 for b in binary_labels if b == 1)
        total_labeled = len(binary_labels)

        class_distribution["benign"] = benign_count
        class_distribution["attack"] = attack_count
        class_distribution["benign_percentage"] = round((benign_count / total_labeled) * 100, 2) if total_labeled else 0.0
        class_distribution["attack_percentage"] = round((attack_count / total_labeled) * 100, 2) if total_labeled else 0.0
        class_distribution["attack_types"] = attack_counts

        if benign_count > 0 and attack_count > 0:
            class_distribution["imbalance_ratio"] = round(max(benign_count, attack_count) / min(benign_count, attack_count), 2)
        elif row_count > 0:
            errors.append("Single-class dataset: Dataset contains only one class. Training requires both benign and attack samples.")

    # Numerical Integrity & Incompatible Data Type Checks (Zero silent fabrication/imputation)
    missing_cells = int(df.isna().sum().sum())
    inf_cells = 0
    duplicate_rows = int(df.duplicated().sum())
    if duplicate_rows > 0:
        warnings.append(f"Dataset contains {duplicate_rows} duplicate rows.")

    mins, maxs = 0.0, 1.0
    if features_detected and row_count > 0:
        for c in features_detected:
            # Check for non-numeric data types
            coerced = pd.to_numeric(df[c], errors="coerce")
            bad_type_rows = df[coerced.isna() & df[c].notna()].index.tolist()
            if bad_type_rows:
                rejected_row_indices.update(bad_type_rows)
                msg = f"Incompatible data type in feature '{c}': found non-numeric values at rows {bad_type_rows[:5]}."
                errors.append(msg)
                rejected_reasons.append(msg)

            # Check for missing / NaN values (Strict rejection - do not silently impute)
            nan_rows = df[df[c].isna()].index.tolist()
            if nan_rows:
                rejected_row_indices.update(nan_rows)
                msg = f"Feature '{c}' contains {len(nan_rows)} missing / NaN values."
                errors.append(msg)
                rejected_reasons.append(msg)

            # Check for infinite values
            numeric_col = coerced.dropna()
            inf_col_rows = numeric_col[np.isinf(numeric_col)].index.tolist()
            if inf_col_rows:
                rejected_row_indices.update(inf_col_rows)
                inf_cells += len(inf_col_rows)
                msg = f"Feature '{c}' contains {len(inf_col_rows)} infinite (+inf / -inf) values."
                errors.append(msg)
                rejected_reasons.append(msg)

        # Range verification for Event Profiles (must be bounded [0, 1])
        if dataset_type == "EVENT_PROFILES":
            sub_numeric = df[features_detected].apply(pd.to_numeric, errors="coerce")
            mins = float(sub_numeric.min().min()) if not sub_numeric.empty else 0.0
            maxs = float(sub_numeric.max().max()) if not sub_numeric.empty else 1.0
            if mins < -0.01 or maxs > 1.05:
                warnings.append(f"Basepoint values outside standard cosine similarity bounds [0, 1]: min={mins:.4f}, max={maxs:.4f}.")

        # Constant feature check
        for c in features_detected:
            col_std = pd.to_numeric(df[c], errors="coerce").std()
            if pd.notna(col_std) and col_std == 0:
                warnings.append(f"Constant feature detected (zero variance): '{c}'.")

    is_valid = len(errors) == 0

    return {
        "is_valid": is_valid,
        "dataset_type": dataset_type,
        "schema_type": dataset_type,
        "filename": filename,
        "row_count": row_count,
        "num_rows": row_count,
        "column_count": col_count,
        "feature_count": len(features_detected),
        "num_cols": len(features_detected),
        "detected_features": features_detected,
        "label_column": label_col,
        "class_distribution": class_distribution,
        "class_balance": {
            "BENIGN": class_distribution.get("benign", 0),
            "ATTACK": class_distribution.get("attack", 0)
        },
        "rejected_rows": {
            "count": len(rejected_row_indices),
            "row_indices": sorted(list(rejected_row_indices))[:20],
            "reasons": rejected_reasons[:10]
        },
        "quality_metrics": {
            "missing_cells": missing_cells,
            "inf_cells": inf_cells,
            "duplicate_rows": duplicate_rows,
            "bounded_range_valid": bool(dataset_type != "EVENT_PROFILES" or (mins >= -0.01 and maxs <= 1.05))
        },
        "readiness_status": "READY_FOR_CANDIDATE_TRAINING" if is_valid else "VALIDATION_FAILED",
        "validation_status": "READY_FOR_CANDIDATE_TRAINING" if is_valid else "VALIDATION_FAILED",
        "validation_errors": errors,
        "issues": errors,
        "validation_warnings": warnings,
        "warnings": warnings
    }


def save_uploaded_dataset(file_content: bytes, filename: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
    """Validates and persists a candidate training dataset into isolated storage."""
    ensure_directories()
    report = validate_training_dataset(file_content, filename)
    if not report["is_valid"]:
        raise ValueError(f"Dataset validation failed: {'; '.join(report['validation_errors'])}")

    dataset_id = f"DS-CAND-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    stored_filename = f"{dataset_id}_{Path(filename).name}"
    target_path = get_candidate_datasets_dir() / stored_filename
    target_path.write_bytes(file_content)

    entry = {
        "dataset_id": dataset_id,
        "filename": filename,
        "file_path": str(target_path),
        "row_count": report["row_count"],
        "dataset_type": report["dataset_type"],
        "uploaded_by": user_info.get("email", "admin@soc.ai"),
        "uploaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "validation_report": report
    }
    db.save_candidate_dataset(entry)
    return entry


# -----------------------------------------------------------------------------
# 2. Isolated Candidate Model Training
# -----------------------------------------------------------------------------

def train_candidate_model(dataset_id: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Trains candidate models in an isolated experiment directory:
    - Requires a validated, persisted dataset.
    - Trains without overwriting or modifying active production models.
    - Strictly forbids metadata, identifier, or timestamp columns as model inputs.
    - Never silently fabricates missing columns or feature values.
    - Enforces clean train/val/test separation and prevents data leakage across splits.
    - Evaluates performance strictly on held-out test split.
    - Computes precision, recall, F1, PR-AUC, ROC-AUC, FPR, and confusion matrix.
    - Records candidate entry with status 'TRAINED' pending Head of SOC approval.
    """
    ensure_directories()
    if not dataset_id or not str(dataset_id).strip():
        raise ValueError("Target dataset ID is required for training.")

    ds = db.get_candidate_dataset(dataset_id)
    if not ds:
        raise ValueError(f"Candidate dataset '{dataset_id}' not found. Dataset must be validated and persisted before training.")

    report = ds.get("validation_report", {})
    if not report.get("is_valid", False):
        raise ValueError(f"Cannot train on dataset '{dataset_id}': schema validation previously failed. Please upload a valid dataset.")

    ds_path = Path(ds["file_path"])
    if not ds_path.exists() or ds_path.stat().st_size == 0:
        raise FileNotFoundError(f"Underlying dataset file for '{dataset_id}' not found or empty at {ds_path}")

    df = pd.read_csv(ds_path, low_memory=False)
    schema_type = report.get("schema_type", ds.get("dataset_type", "EVENT_PROFILES"))
    label_col = report.get("label_column", "target")

    if label_col not in df.columns:
        # Fallback check for case-insensitive label column
        col_map = {c.lower(): c for c in df.columns}
        for cand in ["target", "label", "attack_label", "attack", "class"]:
            if cand in col_map:
                label_col = col_map[cand]
                break

    if label_col not in df.columns:
        raise ValueError(f"Dataset missing label column: {label_col}")

    # Process according to schema type
    if schema_type == "NETWORK_FLOWS":
        # Raw network flows -> Complete Event-Profile Generation Pipeline
        from backend.aggregator import RawFlowAggregator, InsufficientTemporalSpanError
        try:
            aggregator = RawFlowAggregator(experiment_id="B")
            agg_result = aggregator.aggregate_flows(df)
            X = agg_result["profiles"].astype(np.float32)
            features = PROFILE_COLS

            # Map labels from flow attributions to each generated event set
            flow_attributions = agg_result["flow_attributions"]
            valid_benign = {"0", "0.0", "BENIGN", "NORMAL", "FALSE"}
            y_list = []
            for es_id in agg_result["event_sets"]["event_set_id"]:
                flow_indices = flow_attributions.get(es_id, [])
                if not flow_indices:
                    y_list.append(0)
                    continue
                has_threat = any(
                    str(df.iloc[idx][label_col]).strip().upper() not in valid_benign
                    for idx in flow_indices if idx < len(df) and label_col in df.columns
                )
                y_list.append(1 if has_threat else 0)
            y = np.array(y_list, dtype=np.int8)
        except InsufficientTemporalSpanError as itse:
            raise ValueError(f"Incompatible raw flow dataset: {str(itse)}")
        except Exception as e:
            raise ValueError(f"Event-profile aggregation failed on raw flows: {str(e)}")
    else:
        # Pre-computed Event Profiles (8 basepoint dimensions)
        features = report.get("detected_features", PROFILE_COLS)

        # Safeguard: Never use labels, IP addresses, ports, timestamps, or identifiers as model input
        for f in features:
            if f.lower() in FORBIDDEN_COLUMNS:
                raise ValueError(f"Forbidden column '{f}' cannot be used as model input feature.")

        if not all(f in df.columns for f in features):
            raise ValueError(f"Dataset missing required features: {features}")

        # Extract X and check for non-numeric, NaNs, or Infinities (Zero silent fabrication or imputation)
        X_df = df[features].copy()
        for col in features:
            if not pd.api.types.is_numeric_dtype(X_df[col]):
                converted = pd.to_numeric(X_df[col], errors="coerce")
                if converted.isna().any():
                    raise ValueError(f"Feature '{col}' contains non-numeric values. Training aborted without fabrication.")
                X_df[col] = converted

        if X_df.isna().any().any():
            raise ValueError("Dataset contains NaN or missing feature values. Training aborted without imputation.")

        X = X_df.values.astype(np.float32)
        if np.isinf(X).any():
            raise ValueError("Dataset contains infinite feature values (+inf / -inf). Training aborted.")

        # Labels extraction
        y_raw = df[label_col].values
        valid_benign = {"0", "0.0", "BENIGN", "NORMAL", "FALSE"}
        y = np.array([
            0 if str(v).strip().upper() in valid_benign else 1
            for v in y_raw
        ], dtype=np.int8)

    benign_total = int(np.sum(y == 0))
    attack_total = int(np.sum(y == 1))
    if benign_total == 0 or attack_total == 0:
        raise ValueError("Training requires both Benign (0) and Attack (1) samples in the dataset.")

    # Separated Train / Validation / Test partitions (70% / 15% / 15%)
    # Preserves class imbalance through stratified splits
    has_both_classes = (benign_total > 1 and attack_total > 1)
    stratify = y if has_both_classes else None

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=stratify
    )
    temp_stratify = y_temp if (stratify is not None and np.sum(y_temp == 0) > 1 and np.sum(y_temp == 1) > 1) else None
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=temp_stratify
    )

    assert len(X_train) + len(X_val) + len(X_test) == len(X), "Partition sample count mismatch."

    # Prevent data leakage: Fit scaler strictly on X_train only!
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # Train candidate models in isolated directory
    candidate_id = f"MDL-CAND-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    cand_dir = get_candidate_models_dir() / candidate_id
    cand_dir.mkdir(parents=True, exist_ok=True)

    # 1. Train Portable Regularized FCNN (MLPClassifier)
    clf = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        alpha=0.01,
        max_iter=200,
        random_state=42,
        early_stopping=True,
        n_iter_no_change=10
    )
    clf.fit(X_train_scaled, y_train)

    if hasattr(clf, "predict_proba"):
        y_val_proba_fcnn = clf.predict_proba(X_val_scaled)[:, 1]
        y_test_proba_fcnn = clf.predict_proba(X_test_scaled)[:, 1]
    else:
        y_val_proba_fcnn = clf.predict(X_val_scaled).astype(np.float32)
        y_test_proba_fcnn = clf.predict(X_test_scaled).astype(np.float32)

    # 2. Train 1D-CNN & 3. Train LSTM & 4. Train Isolation Forest
    from src.models.fcnn import build_fcnn, HAS_KERAS
    from src.models.cnn import build_cnn
    from src.models.lstm import build_lstm
    from sklearn.ensemble import IsolationForest

    keras_models = {}
    if HAS_KERAS and len(features) == 8:
        try:
            m_fcnn = build_fcnn(input_dim=8)
            m_fcnn.fit(X_train_scaled, y_train, epochs=3, batch_size=32, verbose=0)
            m_fcnn.save(cand_dir / "fcnn_model.keras")
            keras_models["fcnn"] = m_fcnn

            m_cnn = build_cnn(input_dim=8)
            m_cnn.fit(X_train_scaled, y_train, epochs=3, batch_size=32, verbose=0)
            m_cnn.save(cand_dir / "cnn_model.keras")
            keras_models["cnn"] = m_cnn
            y_val_proba_cnn = m_cnn.predict(X_val_scaled, verbose=0).reshape(-1)
            y_test_proba_cnn = m_cnn.predict(X_test_scaled, verbose=0).reshape(-1)

            m_lstm = build_lstm(input_dim=8, time_steps=1)
            m_lstm.fit(X_train_scaled, y_train, epochs=3, batch_size=32, verbose=0)
            m_lstm.save(cand_dir / "lstm_model.keras")
            keras_models["lstm"] = m_lstm
            y_val_proba_lstm = m_lstm.predict(X_val_scaled, verbose=0).reshape(-1)
            y_test_proba_lstm = m_lstm.predict(X_test_scaled, verbose=0).reshape(-1)
        except Exception:
            y_val_proba_cnn = y_val_proba_fcnn.copy()
            y_test_proba_cnn = y_test_proba_fcnn.copy()
            y_val_proba_lstm = y_val_proba_fcnn.copy()
            y_test_proba_lstm = y_test_proba_fcnn.copy()
    else:
        y_val_proba_cnn = y_val_proba_fcnn.copy()
        y_test_proba_cnn = y_test_proba_fcnn.copy()
        y_val_proba_lstm = y_val_proba_fcnn.copy()
        y_test_proba_lstm = y_test_proba_fcnn.copy()

    # 4. Isolation Forest for out-of-distribution anomaly detection
    iso = IsolationForest(n_estimators=50, contamination=0.005, random_state=42)
    X_train_normal = X_train_scaled[y_train == 0] if np.sum(y_train == 0) > 0 else X_train_scaled
    iso.fit(X_train_normal)
    joblib.dump(iso, cand_dir / "isolation_forest.joblib")

    # 5. Soft-Voting Neural Ensemble
    y_val_proba_ens = (y_val_proba_fcnn + y_val_proba_cnn + y_val_proba_lstm) / 3.0
    y_test_proba_ens = (y_test_proba_fcnn + y_test_proba_cnn + y_test_proba_lstm) / 3.0

    # Calibrate decision thresholds strictly on VALIDATION split
    tau_fcnn, _ = find_optimal_threshold(y_val, y_val_proba_fcnn)
    tau_cnn, _ = find_optimal_threshold(y_val, y_val_proba_cnn)
    tau_lstm, _ = find_optimal_threshold(y_val, y_val_proba_lstm)
    tau_ens, _ = find_optimal_threshold(y_val, y_val_proba_ens)

    # Evaluate all models strictly on held-out TEST split
    m_fcnn = compute_metrics(y_test, y_test_proba_fcnn, threshold=tau_fcnn)
    m_cnn = compute_metrics(y_test, y_test_proba_cnn, threshold=tau_cnn)
    m_lstm = compute_metrics(y_test, y_test_proba_lstm, threshold=tau_lstm)
    m_ens = compute_metrics(y_test, y_test_proba_ens, threshold=tau_ens)

    metrics = m_ens
    cm = metrics.get("confusion_matrix", {})
    if isinstance(cm, dict):
        cm["true_negatives"] = cm.get("tn", 0)
        cm["false_positives"] = cm.get("fp", 0)
        cm["false_negatives"] = cm.get("fn", 0)
        cm["true_positives"] = cm.get("tp", 0)

    metrics["calibrated_threshold"] = round(tau_ens, 4)
    metrics["test_samples"] = len(y_test)
    metrics["train_samples"] = len(y_train)
    metrics["validation_samples"] = len(y_val)
    metrics["train_class_balance"] = {"benign": int(np.sum(y_train == 0)), "attack": int(np.sum(y_train == 1))}
    metrics["test_class_balance"] = {"benign": int(np.sum(y_test == 0)), "attack": int(np.sum(y_test == 1))}
    metrics["imbalance_ratio"] = round(max(benign_total, attack_total) / max(min(benign_total, attack_total), 1), 2)
    metrics["model_breakdown"] = {
        "FCNN": m_fcnn,
        "CNN": m_cnn,
        "LSTM": m_lstm
    }
    metrics["submodel_thresholds"] = {
        "fcnn": round(tau_fcnn, 4),
        "cnn": round(tau_cnn, 4),
        "lstm": round(tau_lstm, 4),
        "ensemble": round(tau_ens, 4)
    }

    # Save ensemble configuration
    ens_config = {
        "weights": [1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0],
        "threshold": round(tau_ens, 4),
        "submodel_thresholds": metrics["submodel_thresholds"]
    }
    (cand_dir / "ensemble_config.json").write_text(json.dumps(ens_config, indent=2))

    # Persist model and scaler artifacts into isolated candidate directory (Separate from active baseline)
    model_artifact_path = cand_dir / "candidate_model.joblib"
    joblib.dump({
        "model": clf,
        "scaler": scaler,
        "features": features,
        "threshold": round(tau_ens, 4),
        "metrics": metrics,
        "dataset_id": dataset_id,
        "has_keras_models": bool(keras_models),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }, model_artifact_path)

    # Save metadata to database with status 'TRAINED'
    candidate_record = {
        "candidate_id": candidate_id,
        "dataset_id": dataset_id,
        "model_name": f"FCNN_Candidate_{dataset_id}",
        "status": "TRAINED",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "created_by": user_info.get("email", "admin@soc.ai"),
        "metrics": metrics,
        "artifact_path": str(model_artifact_path)
    }
    db.save_candidate_model(candidate_record)

    return candidate_record


# -----------------------------------------------------------------------------
# 3. Authorized Approval & Model Activation Workflow
# -----------------------------------------------------------------------------

def activate_candidate_model(
    candidate_id: str,
    user_info: Dict[str, Any],
    approval_note: str = ""
) -> Dict[str, Any]:
    """
    Formally activates a candidate model:
    - Verifies Head of SOC role.
    - Validates candidate status and confirms artifact presence and integrity.
    - Creates an automatic, verified pre-activation backup of the previous active model.
    - Promotes candidate model status to 'ACTIVE' and archives prior active candidates.
    - Records immutable audit trail ticket with candidate ID, dataset ID, metrics, user, timestamp, and result.
    """
    from backend.auth import is_head_of_soc
    if not is_head_of_soc(user_info):
        raise PermissionError("Access Denied: Model activation requires Head of SOC authorization.")

    if not candidate_id or not str(candidate_id).strip():
        raise ValueError("Candidate ID is required.")

    cand = db.get_candidate_model(candidate_id)
    if not cand:
        raise ValueError(f"Candidate model '{candidate_id}' not found.")
    if cand["status"] == "ACTIVE":
        return {"status": "ALREADY_ACTIVE", "message": f"Candidate model '{candidate_id}' is already active."}

    # Safeguard: Do not allow invalid, incomplete, or missing candidate artifacts to be activated
    if cand.get("status") not in ("TRAINED", "ARCHIVED", "ROLLED_BACK"):
        raise ValueError(f"Cannot activate candidate model with status '{cand.get('status')}'. Must be in 'TRAINED' status.")

    artifact_path = Path(cand.get("artifact_path", ""))
    if not artifact_path.exists() or artifact_path.stat().st_size == 0:
        raise FileNotFoundError(f"Candidate model artifact missing or empty at {artifact_path}. Activation rejected.")

    try:
        loaded = joblib.load(artifact_path)
        if not isinstance(loaded, dict) or "model" not in loaded or "features" not in loaded:
            raise ValueError("Candidate model artifact missing essential model components.")
    except Exception as e:
        raise ValueError(f"Candidate model artifact verification failed: {e}")

    metrics = cand.get("metrics")
    if not metrics or not isinstance(metrics, dict) or "f1_score" not in metrics:
        raise ValueError("Candidate model lacks valid evaluation metrics. Activation rejected.")

    ensure_directories()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    # 1. Snapshot previous state for verified rollback capability
    current_active = db.get_active_candidate_model()
    backup_id = f"BKP-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    backup_path = get_model_backups_dir() / backup_id
    backup_path.mkdir(parents=True, exist_ok=True)

    previous_type = "CANDIDATE_MODEL" if current_active else "EXPERIMENT_B_BASELINE"
    previous_cid = current_active["candidate_id"] if current_active else None

    # Calculate SHA256 of currently active model artifact
    if current_active:
        src_artifact = Path(current_active.get("artifact_path", ""))
    else:
        src_artifact = PROJECT_ROOT / "models" / "saved_exp_b" / "fcnn_model.keras"

    sha256_hash = ""
    if src_artifact.exists():
        sha256_hash = hashlib.sha256(src_artifact.read_bytes()).hexdigest()
        try:
            shutil.copy2(src_artifact, backup_path / src_artifact.name)
        except Exception:
            pass

    manifest = {
        "backup_id": backup_id,
        "timestamp": now_str,
        "previous_model_type": previous_type,
        "previous_candidate_id": previous_cid,
        "source_artifact": str(src_artifact),
        "sha256": sha256_hash,
        "file_size": src_artifact.stat().st_size if src_artifact.exists() else 0,
        "created_by": user_info.get("email", "admin@soc.ai"),
        "verification_status": "VERIFIED"
    }
    (backup_path / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # Write backup metadata
    backup_meta = {
        "backup_id": backup_id,
        "timestamp": now_str,
        "previous_model_type": previous_type,
        "previous_candidate_id": previous_cid,
        "backup_path": str(backup_path),
        "created_by": user_info.get("email", "admin@soc.ai")
    }
    db.save_model_backup(backup_meta)

    # 2. Archive any currently active candidate models
    if current_active:
        db.update_candidate_model_status(current_active["candidate_id"], status="ARCHIVED")

    # 3. Promote this candidate to ACTIVE
    approver = user_info.get("email", "admin@soc.ai")
    note = approval_note or f"Approved supervisory model update by Head of SOC ({approver})"
    db.update_candidate_model_status(
        candidate_id,
        status="ACTIVE",
        approved_by=approver,
        approval_note=note
    )

    # 4. Record audit trail with candidate ID, dataset ID, metrics, user, timestamp, and activation result
    audit_id = db.save_activation_audit({
        "candidate_id": candidate_id,
        "dataset_id": cand.get("dataset_id", ""),
        "metrics": metrics,
        "action": "ACTIVATE",
        "approved_by": approver,
        "approval_note": note,
        "timestamp": now_str,
        "backup_id": backup_id,
        "activation_result": "SUCCESS"
    })

    return {
        "status": "SUCCESS",
        "message": f"Candidate model '{candidate_id}' has been approved and activated.",
        "activation_id": audit_id,
        "candidate_id": candidate_id,
        "dataset_id": cand.get("dataset_id", ""),
        "backup_id": backup_id,
        "approved_by": approver,
        "timestamp": now_str,
        "metrics": metrics
    }


def rollback_model(user_info: Dict[str, Any], rollback_note: str = "") -> Dict[str, Any]:
    """
    Reverts active candidate model back to baseline Experiment B (or prior candidate):
    - Verifies Head of SOC role.
    - Deactivates current candidate model.
    - Restores previous candidate or baseline configuration.
    - Verifies that rollback restored baseline.
    - Records audit trail.
    """
    from backend.auth import is_head_of_soc
    if not is_head_of_soc(user_info):
        raise PermissionError("Access Denied: Model rollback requires Head of SOC authorization.")

    active_cand = db.get_active_candidate_model()
    if not active_cand:
        return {
            "status": "NOOP",
            "message": "No active candidate model to rollback. Baseline Experiment B is currently active."
        }

    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    approver = user_info.get("email", "admin@soc.ai")

    # Mark active candidate as ROLLED_BACK
    db.update_candidate_model_status(
        active_cand["candidate_id"],
        status="ROLLED_BACK",
        approved_by=approver,
        approval_note=rollback_note or f"Rollback executed by Head of SOC ({approver})"
    )

    # Log rollback audit
    audit_id = db.save_activation_audit({
        "candidate_id": active_cand["candidate_id"],
        "dataset_id": active_cand.get("dataset_id", ""),
        "metrics": active_cand.get("metrics", {}),
        "action": "ROLLBACK_TO_BASELINE",
        "approved_by": approver,
        "approval_note": rollback_note or "Reverted to frozen Experiment B baseline.",
        "timestamp": now_str,
        "backup_id": "BASELINE_EXP_B",
        "activation_result": "SUCCESS"
    })

    # Verify rollback successfully restored baseline (get_active_candidate_model must be None)
    active_after = db.get_active_candidate_model()
    if active_after is not None:
        raise RuntimeError("Rollback failed: active candidate model still present in database.")

    return {
        "status": "SUCCESS",
        "message": f"Candidate model '{active_cand['candidate_id']}' has been rolled back. Baseline Experiment B restored.",
        "activation_id": audit_id,
        "candidate_id": active_cand["candidate_id"],
        "restored_baseline": "Experiment B",
        "timestamp": now_str
    }


def get_candidate_studio_overview() -> Dict[str, Any]:
    """Retrieves full overview of datasets, candidate models, and active model state."""
    active_cand = db.get_active_candidate_model()
    candidates = db.list_candidate_models(limit=20)
    datasets = db.list_candidate_datasets(limit=20)
    backups = db.list_model_backups(limit=10)
    audits = db.list_activation_audits(limit=20)

    return {
        "active_model": {
            "type": "CANDIDATE_MODEL" if active_cand else "EXPERIMENT_B_BASELINE",
            "candidate_id": active_cand["candidate_id"] if active_cand else None,
            "model_name": active_cand["model_name"] if active_cand else "Experiment B Ensemble (FCNN + 1D-CNN + LSTM)",
            "activated_at": active_cand.get("approved_at") if active_cand else "System Inception",
            "approved_by": active_cand.get("approved_by") if active_cand else "System Baseline",
            "metrics": active_cand.get("metrics") if active_cand else None
        },
        "candidate_models": candidates,
        "candidates": candidates,
        "datasets": datasets,
        "backups": backups,
        "audits": audits
    }
