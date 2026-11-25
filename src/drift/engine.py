"""
Dual-Layer Data Drift Detection Engine for AI-SIEM.

Monitors statistical distribution shifts between the baseline training distributions
and newly ingested network traffic across two layers:
  - Layer 1: Network Feature Drift (flow_duration, flow_bytes_s, flow_packets_s, syn_flag_count)
             Calculates per-feature PSI, KS-statistic (with p-value), and normalized 1-Wasserstein distance.
  - Layer 2: Event Profile Drift (bp_01 through bp_08 & Dominant Basepoint Distribution)
             Calculates per-basepoint KS, PSI, normalized Wasserstein distance,
             and dominant basepoint categorical Jensen-Shannon distance.

Overall Drift Score:
  - Equal weighting (0.5 * Layer 1 + 0.5 * Layer 2) when both layers are present.
  - Transparent partial evaluation when only one layer is available (flagged as PARTIAL).
  - Status thresholds:
      < 0.25: LOW
      0.25 - 0.50: MODERATE
      >= 0.50: SIGNIFICANT (triggers training dataset update recommendation alert).
"""

import logging
import math
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

from .baseline import (
    PROFILE_FEATURES,
    RAW_FEATURES,
    extract_distribution_summary,
    load_reference_baseline,
)

logger = logging.getLogger(__name__)


def compute_psi(actual: np.ndarray, ref_deciles: List[float], epsilon: float = 1e-4) -> Tuple[float, float]:
    """
    Computes Population Stability Index (PSI) and a normalized [0, 1] PSI score.

    ref_deciles: 11 values [q0, q10, ..., q100] defining 10 bins.
    Returns:
      psi: Raw non-negative PSI statistic.
      psi_score: Normalized score in [0, 1] mapped as min(1.0, psi / 0.50).
    """
    cleaned = actual[np.isfinite(actual)]
    n_act = len(cleaned)
    if n_act == 0 or len(ref_deciles) < 11:
        return 0.0, 0.0

    ref_d = np.array(ref_deciles, dtype=np.float64)
    unique_edges = np.unique(ref_d)
    if len(unique_edges) < 2:
        return 0.0, 0.0

    # Calculate expected proportions for intervals between unique edges
    cdf_at_unique = []
    for u in unique_edges:
        k = np.max(np.where(ref_d <= u)[0])
        cdf_at_unique.append(k / 10.0)

    props = np.diff(cdf_at_unique)
    if np.sum(props) > 0:
        p = props / np.sum(props)
    else:
        p = np.full(len(unique_edges) - 1, 1.0 / (len(unique_edges) - 1))

    # Form histogram bins with extended outer bounds
    hist_bins = unique_edges.copy()
    hist_bins[0] = -np.inf
    hist_bins[-1] = np.inf

    counts, _ = np.histogram(cleaned, bins=hist_bins)
    q = counts.astype(np.float64) / n_act

    # Smoothing with epsilon to avoid division by zero or log(0)
    p_smooth = (p + epsilon) / (1.0 + len(p) * epsilon)
    q_smooth = (q + epsilon) / (1.0 + len(q) * epsilon)

    psi = float(np.sum((q_smooth - p_smooth) * np.log(q_smooth / p_smooth)))
    psi = max(0.0, psi)
    # PSI mapping: 0.10 is minor shift, 0.25 is moderate, >= 0.50 is severe
    psi_score = min(1.0, psi / 0.50)

    return psi, psi_score


def compute_ks(actual: np.ndarray, ref_quantiles_100: List[float], n_ref: int = 1614510) -> Tuple[float, float]:
    """
    Computes Kolmogorov-Smirnov (KS) statistic D_KS and asymptotic p-value
    by comparing empirical CDF of actual data against reference quantile distribution.

    Returns:
      ks_stat: Maximum absolute CDF difference in [0, 1].
      p_value: Two-sided asymptotic p-value.
    """
    cleaned = actual[np.isfinite(actual)]
    n_act = len(cleaned)
    if n_act == 0 or len(ref_quantiles_100) < 101:
        return 0.0, 1.0

    ref_q = np.array(ref_quantiles_100, dtype=np.float64)
    unique_points = np.unique(ref_q)

    # Reference CDF at each unique value x: fraction of reference data <= x
    # Since ref_q[k] is the k-th percentile (k=0..100):
    ref_cdf = np.array([
        np.max(np.where(ref_q <= pt)[0]) / 100.0
        for pt in unique_points
    ], dtype=np.float64)

    # Actual empirical CDF evaluated at the same unique points
    sorted_act = np.sort(cleaned)
    act_cdf = np.searchsorted(sorted_act, unique_points, side="right") / float(n_act)

    d_ks = float(np.max(np.abs(act_cdf - ref_cdf)))
    d_ks = min(1.0, max(0.0, d_ks))

    # Asymptotic KS two-sided p-value calculation
    n_eff = math.sqrt((n_act * n_ref) / (n_act + n_ref))
    lambda_val = (n_eff + 0.12 + 0.11 / n_eff) * d_ks
    if lambda_val <= 0.0:
        p_value = 1.0
    else:
        # Sum Kolmogorov series terms
        sum_terms = 0.0
        for k in range(1, 101):
            term = 2.0 * ((-1) ** (k - 1)) * math.exp(-2.0 * (k * lambda_val) ** 2)
            sum_terms += term
            if abs(term) < 1e-10:
                break
        p_value = min(1.0, max(0.0, sum_terms))

    return d_ks, float(p_value)


def compute_wasserstein(
    actual: np.ndarray,
    ref_quantiles_100: List[float],
    ref_iqr: float,
    is_bounded_unit_interval: bool = False,
) -> Tuple[float, float, float]:
    """
    Computes 1-Wasserstein (Earth Mover's Distance) via 101 quantile integration:
      W_1 = integral_0^1 |F_actual^{-1}(t) - F_ref^{-1}(t)| dt
    
    Normalizes by reference IQR (or unit interval for profile dimensions).
    Returns:
      w_raw: Raw Wasserstein distance in feature units.
      w_norm: Normalized Wasserstein distance (w_raw / ref_iqr).
      w_score: Bounded score strictly in [0, 1].
    """
    cleaned = actual[np.isfinite(actual)]
    if len(cleaned) == 0 or len(ref_quantiles_100) < 101:
        return 0.0, 0.0, 0.0

    percentiles_100 = np.linspace(0, 100, 101)
    act_quantiles = np.percentile(cleaned, percentiles_100)
    ref_quantiles = np.array(ref_quantiles_100, dtype=np.float64)

    w_raw = float(np.mean(np.abs(act_quantiles - ref_quantiles)))
    w_raw = max(0.0, w_raw)

    if is_bounded_unit_interval:
        # For event profile dimensions, values are already bounded in [0, 1]
        w_norm = w_raw
        w_score = min(1.0, w_raw)
    else:
        # For continuous raw network features, normalize by reference IQR
        scale = ref_iqr if ref_iqr > 1e-9 else 1.0
        w_norm = float(w_raw / scale)
        # Smoothly map normalized distance to [0, 1] via 1 - exp(-w_norm)
        w_score = float(1.0 - math.exp(-w_norm))
        w_score = min(1.0, max(0.0, w_score))

    return w_raw, w_norm, w_score


def compute_js_distance(
    actual_dominant_distribution: Dict[str, float],
    ref_dominant_distribution: Dict[str, float],
    epsilon: float = 1e-6,
) -> Tuple[float, float]:
    """
    Computes Jensen-Shannon Divergence (JSD) and normalized Jensen-Shannon Distance:
      S_JS = sqrt(JSD) in [0, 1]
    across categorical basepoint distributions (bp_01 through bp_08).
    """
    keys = [f"bp_{i:02d}" for i in range(1, 9)]
    p = np.array([ref_dominant_distribution.get(k, 0.0) for k in keys], dtype=np.float64)
    q = np.array([actual_dominant_distribution.get(k, 0.0) for k in keys], dtype=np.float64)

    # Smooth and re-normalize
    p = (p + epsilon) / np.sum(p + epsilon)
    q = (q + epsilon) / np.sum(q + epsilon)

    m = 0.5 * (p + q)
    # JSD in base 2 so range is strictly [0, 1]
    kl_pm = np.sum(p * np.log2(p / m))
    kl_qm = np.sum(q * np.log2(q / m))
    jsd = float(0.5 * kl_pm + 0.5 * kl_qm)
    jsd = min(1.0, max(0.0, jsd))
    js_distance = float(math.sqrt(jsd))

    return jsd, js_distance


class DriftEngine:
    """
    Evaluates dual-layer data drift against precalculated Experiment B reference baselines.
    """

    def __init__(self, baseline_path: Optional[str] = None):
        self.baseline = load_reference_baseline(baseline_path)
        self.experiment = self.baseline.get("experiment", "exp_b")
        self.full_ref = self.baseline["full_reference"]
        self.benign_ref = self.baseline["benign_reference"]

    def evaluate_network_features(
        self,
        df_flows: pd.DataFrame,
        population: str = "full",
    ) -> Dict[str, Any]:
        """
        Evaluates Layer 1 Network Feature Drift across the 4 verified features:
        flow_duration, flow_bytes_s, flow_packets_s, syn_flag_count.
        """
        ref_data = self.benign_ref["network_features"] if population == "benign" else self.full_ref["network_features"]
        n_ref = self.baseline.get("n_benign_training_flows" if population == "benign" else "n_training_flows", 1614510)

        feature_metrics = {}
        feature_scores = []

        for feat in RAW_FEATURES:
            if feat not in df_flows.columns:
                logger.warning(f"Feature '{feat}' missing from incoming flows.")
                continue

            series = df_flows[feat]
            arr = series.replace([np.inf, -np.inf], np.nan).dropna().to_numpy(dtype=np.float64)
            if len(arr) == 0:
                continue

            ref_f = ref_data.get(feat, {})
            ref_deciles = ref_f.get("deciles", [])
            ref_quantiles = ref_f.get("quantiles_100", [])
            ref_iqr = ref_f.get("iqr", 1.0)

            psi, psi_score = compute_psi(arr, ref_deciles)
            d_ks, p_val = compute_ks(arr, ref_quantiles, n_ref=n_ref)
            w_raw, w_norm, w_score = compute_wasserstein(arr, ref_quantiles, ref_iqr, is_bounded_unit_interval=False)

            # Composite feature drift score: equal 1/3 weighting of KS, PSI, and normalized Wasserstein
            f_score = float((d_ks + psi_score + w_score) / 3.0)
            feature_scores.append(f_score)

            feature_metrics[feat] = {
                "count": int(len(arr)),
                "actual_mean": float(np.mean(arr)),
                "actual_std": float(np.std(arr)),
                "reference_mean": float(ref_f.get("mean", 0.0)),
                "reference_std": float(ref_f.get("std", 0.0)),
                "psi": round(psi, 4),
                "psi_score": round(psi_score, 4),
                "ks_statistic": round(d_ks, 4),
                "ks_pvalue": round(p_val, 6),
                "wasserstein_raw": round(w_raw, 4),
                "wasserstein_normalized": round(w_norm, 4),
                "wasserstein_score": round(w_score, 4),
                "feature_drift_score": round(f_score, 4),
            }

        layer1_score = float(np.mean(feature_scores)) if feature_scores else 0.0
        return {
            "score": round(layer1_score, 4),
            "n_evaluated_features": len(feature_metrics),
            "features": feature_metrics,
        }

    def evaluate_event_profiles(
        self,
        profiles_matrix: Union[np.ndarray, pd.DataFrame],
        population: str = "full",
    ) -> Dict[str, Any]:
        """
        Evaluates Layer 2 Event Profile Drift across bp_01 to bp_08
        and dominant basepoint categorical distribution.
        """
        if isinstance(profiles_matrix, pd.DataFrame):
            # Select profile columns if named, otherwise assume first 8 columns
            cols = [c for c in PROFILE_FEATURES if c in profiles_matrix.columns]
            if len(cols) == 8:
                mat = profiles_matrix[cols].to_numpy(dtype=np.float64)
            else:
                mat = profiles_matrix.iloc[:, :8].to_numpy(dtype=np.float64)
        else:
            mat = np.asarray(profiles_matrix, dtype=np.float64)

        if len(mat) == 0:
            return {
                "score": 0.0,
                "basepoint_metrics": {},
                "dominant_basepoint_distribution": {},
                "js_divergence": 0.0,
                "js_distance": 0.0,
            }

        ref_prof = self.benign_ref["event_profiles"] if population == "benign" else self.full_ref["event_profiles"]
        ref_dom = (
            self.benign_ref["dominant_basepoint_distribution"]
            if population == "benign"
            else self.full_ref["dominant_basepoint_distribution"]
        )
        n_ref = self.baseline.get("n_benign_training_profiles" if population == "benign" else "n_training_profiles", 1997495)

        bp_metrics = {}
        bp_scores = []

        for idx, bp_name in enumerate(PROFILE_FEATURES):
            if idx >= mat.shape[1]:
                break
            arr = mat[:, idx]
            cleaned = arr[np.isfinite(arr)]
            if len(cleaned) == 0:
                continue

            ref_bp = ref_prof.get(bp_name, {})
            ref_deciles = ref_bp.get("deciles", [])
            ref_quantiles = ref_bp.get("quantiles_100", [])
            ref_iqr = ref_bp.get("iqr", 1.0)

            psi, psi_score = compute_psi(cleaned, ref_deciles)
            d_ks, p_val = compute_ks(cleaned, ref_quantiles, n_ref=n_ref)
            w_raw, w_norm, w_score = compute_wasserstein(cleaned, ref_quantiles, ref_iqr, is_bounded_unit_interval=True)

            score_bp = float((d_ks + psi_score + w_score) / 3.0)
            bp_scores.append(score_bp)

            bp_metrics[bp_name] = {
                "count": int(len(cleaned)),
                "actual_mean": float(np.mean(cleaned)),
                "actual_std": float(np.std(cleaned)),
                "reference_mean": float(ref_bp.get("mean", 0.0)),
                "reference_std": float(ref_bp.get("std", 0.0)),
                "psi": round(psi, 4),
                "psi_score": round(psi_score, 4),
                "ks_statistic": round(d_ks, 4),
                "ks_pvalue": round(p_val, 6),
                "wasserstein_raw": round(w_raw, 4),
                "wasserstein_normalized": round(w_norm, 4),
                "wasserstein_score": round(w_score, 4),
                "dimension_drift_score": round(score_bp, 4),
            }

        mean_bp_score = float(np.mean(bp_scores)) if bp_scores else 0.0

        # Dominant basepoint distribution
        from .baseline import compute_dominant_basepoint_distribution
        act_dom = compute_dominant_basepoint_distribution(mat)
        jsd, js_distance = compute_js_distance(act_dom, ref_dom)

        # Composite Layer 2 score: 50% continuous basepoints, 50% categorical dominant basepoint distribution
        layer2_score = float(0.5 * mean_bp_score + 0.5 * js_distance)

        return {
            "score": round(layer2_score, 4),
            "basepoint_dimension_score": round(mean_bp_score, 4),
            "basepoints": bp_metrics,
            "dominant_basepoint_distribution_actual": act_dom,
            "dominant_basepoint_distribution_reference": ref_dom,
            "js_divergence": round(jsd, 4),
            "js_distance": round(js_distance, 4),
        }

    def evaluate_drift(
        self,
        df_flows: Optional[pd.DataFrame] = None,
        profiles_matrix: Optional[Union[np.ndarray, pd.DataFrame]] = None,
        population: str = "full",
        session_id: Optional[str] = None,
        upload_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes complete Dual-Layer Drift Evaluation.
        
        Handles:
          - Both layers present -> 50% Layer 1 + 50% Layer 2 (COMPLETE)
          - Layer 1 only -> 100% Layer 1 (PARTIAL, Layer 2 omitted)
          - Layer 2 only -> 100% Layer 2 (PARTIAL, Layer 1 omitted)
          - Evaluates drift against reference baselines.
          - Determines LOW / MODERATE / SIGNIFICANT status and recommendation alert.
        """
        has_flows = df_flows is not None and len(df_flows) > 0
        has_profiles = profiles_matrix is not None and len(profiles_matrix) > 0

        if not has_flows and not has_profiles:
            raise ValueError("At least one layer (df_flows or profiles_matrix) must be provided.")

        layer1_result = None
        layer2_result = None
        is_partial = False
        omitted_layer = None

        if has_flows:
            layer1_result = self.evaluate_network_features(df_flows, population=population)

        if has_profiles:
            layer2_result = self.evaluate_event_profiles(profiles_matrix, population=population)

        if has_flows and has_profiles:
            overall_score = 0.5 * layer1_result["score"] + 0.5 * layer2_result["score"]
        elif has_flows:
            overall_score = layer1_result["score"]
            is_partial = True
            omitted_layer = "Layer 2: Event Profiles"
        else:
            overall_score = layer2_result["score"]
            is_partial = True
            omitted_layer = "Layer 1: Network Features"

        overall_score = round(float(overall_score), 4)

        # Status classification
        if overall_score < 0.25:
            drift_status = "LOW"
            recommendation_alert = False
            recommendation_message = (
                f"Data distributions are within expected operational parameters (drift score: {overall_score * 100:.1f}%). "
                "No training dataset update is required at this time."
            )
        elif overall_score < 0.50:
            drift_status = "MODERATE"
            recommendation_alert = False
            recommendation_message = (
                f"Moderate data drift observed (drift score: {overall_score * 100:.1f}%). "
                "Feature and profile distributions show mild variance but remain within operational tolerance. Monitor subsequent uploads."
            )
        else:
            drift_status = "SIGNIFICANT"
            recommendation_alert = True
            recommendation_message = (
                f"Significant data drift detected (drift score: {overall_score * 100:.1f}%). "
                "Incoming network traffic deviates substantially from the baseline training distributions. "
                "It is strongly recommended to review incoming patterns and update/augment the model training dataset."
            )

        report = {
            "session_id": session_id,
            "upload_id": upload_id,
            "reference_experiment": self.experiment,
            "reference_population": population,
            "is_partial": is_partial,
            "omitted_layer": omitted_layer,
            "overall_drift_score": overall_score,
            "overall_drift_percentage": round(overall_score * 100.0, 2),
            "drift_status": drift_status,
            "recommendation_alert": recommendation_alert,
            "recommendation_message": recommendation_message,
            "layer1_network_features": layer1_result,
            "layer2_event_profiles": layer2_result,
        }

        return report
