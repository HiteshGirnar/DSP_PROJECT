"""
core/detection.py
------------------
Reusable rule-based + ML (Isolation Forest) threat detection over the
telemetry dataframe produced by core.data_gen.generate_dataset().
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

HOSPITAL_PREFIXES = ("10.20.1.", "10.20.2.", "10.20.3.")
OLD_FW = {"v2.0.0", "v2.1.4", "v1.9.9"}

STRIDE_MAP = {
    "spoofed_vital_reading":   "Tampering",
    "brute_force_auth":        "Spoofing",
    "replay_attack":           "Repudiation",
    "unauthorized_ip_access":  "Elevation of Privilege",
    "denial_of_service_burst": "Denial of Service",
    "firmware_downgrade":      "Tampering",
}


def run_rule_based(df, dos_threshold=20, zscore_threshold=4):
    df = df.copy()
    flags = pd.Series(False, index=df.index)
    reason = pd.Series("", index=df.index)

    mask = ~df["source_ip"].astype(str).str.startswith(HOSPITAL_PREFIXES)
    flags |= mask; reason[mask] += "external_ip;"

    mask = df["request_count_per_min"] > dos_threshold
    flags |= mask; reason[mask] += "high_request_rate;"

    mask = df["auth_status"] == "failed"
    flags |= mask; reason[mask] += "auth_failed;"

    mask = df["firmware_version"].isin(OLD_FW)
    flags |= mask; reason[mask] += "vulnerable_firmware;"

    df["reading_zscore"] = (
        df.groupby("device_type")["reading_value"]
          .transform(lambda x: (x - x.mean()) / x.std(ddof=0))
    )
    mask = df["reading_zscore"].abs() > zscore_threshold
    mask = mask.fillna(False)
    flags |= mask; reason[mask] += "extreme_zscore;"

    df["rule_flag"] = flags
    df["rule_reason"] = reason
    return df


def run_isolation_forest(df, contamination=0.02, random_state=42):
    df = df.copy()
    feature_cols = ["reading_value", "battery_pct", "signal_strength_dbm", "request_count_per_min"]
    ml_df = df[feature_cols].fillna(df[feature_cols].median())
    iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=random_state)
    pred = iso.fit_predict(ml_df)
    df["ml_flag"] = pred == -1
    return df


def evaluate_detectors(df):
    truth_positive = df["threat_label"] != 0
    rows = []
    for name, pred_col in [("rule_based", "rule_flag"), ("isolation_forest", "ml_flag"), ("combined", "combined_flag")]:
        pred = df[pred_col]
        tp = int((pred & truth_positive).sum())
        fp = int((pred & ~truth_positive).sum())
        fn = int((~pred & truth_positive).sum())
        tn = int((~pred & ~truth_positive).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        rows.append({"detector": name, "true_positives": tp, "false_positives": fp,
                      "false_negatives": fn, "true_negatives": tn,
                      "precision": round(precision, 3), "recall": round(recall, 3), "f1_score": round(f1, 3)})
    return pd.DataFrame(rows)


def run_full_detection(df, dos_threshold=20, zscore_threshold=4, contamination=0.02):
    """Runs rule-based + ML detection, combines flags, returns (df, performance_df, flagged_df)."""
    df = run_rule_based(df, dos_threshold, zscore_threshold)
    df = run_isolation_forest(df, contamination)
    df["combined_flag"] = df["rule_flag"] | df["ml_flag"]

    perf_df = evaluate_detectors(df)

    flagged = df[df["combined_flag"]].copy()
    flagged["detected_by"] = np.where(
        flagged["rule_flag"] & flagged["ml_flag"], "rule+ml",
        np.where(flagged["rule_flag"], "rule_only", "ml_only")
    )
    flagged["stride_category"] = flagged["threat_name"].map(STRIDE_MAP).fillna("Under Review")

    return df, perf_df, flagged


def device_risk_summary(df):
    summary = (
        df.groupby("device_type")
          .agg(total_readings=("record_id", "count"),
               flagged_events=("combined_flag", "sum"),
               unique_devices=("device_id", "nunique"),
               distinct_patients=("patient_id", "nunique"))
          .reset_index()
    )
    summary["flag_rate_pct"] = (summary["flagged_events"] / summary["total_readings"] * 100).round(2)
    return summary.sort_values("flag_rate_pct", ascending=False)
