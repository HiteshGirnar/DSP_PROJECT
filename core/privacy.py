"""
core/privacy.py
----------------
Reusable privacy risk analysis: k-anonymity re-identification check and
a static data-sensitivity classification table.
"""

import pandas as pd


def k_anonymity_report(df, quasi_identifiers=("ward", "device_type", "hour")):
    df = df.copy()
    if "hour" not in df.columns and "timestamp" in df.columns:
        df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour

    qi = list(quasi_identifiers)
    group_sizes = (
        df.groupby(qi)["patient_id"]
          .nunique()
          .reset_index(name="k_distinct_patients")
    )
    group_sizes["risk_level"] = pd.cut(
        group_sizes["k_distinct_patients"],
        bins=[-1, 2, 5, 10, 1e9],
        labels=["CRITICAL (k<=2)", "HIGH (k<=5)", "MODERATE (k<=10)", "LOW (k>10)"],
    )
    return group_sizes.sort_values("k_distinct_patients")


def data_classification_table():
    return pd.DataFrame([
        {"field": "patient_id",             "category": "Pseudonymous identifier", "sensitivity": "High",   "phi_hipaa": "Yes (linkable)",  "notes": "Direct link to a specific patient's record"},
        {"field": "reading_value (vitals)", "category": "Health data",             "sensitivity": "High",   "phi_hipaa": "Yes",              "notes": "Clinical vital signs; core PHI"},
        {"field": "device_id",              "category": "Device metadata",        "sensitivity": "Medium", "phi_hipaa": "Indirect",         "notes": "Combined w/ timing can re-identify (k-anonymity risk)"},
        {"field": "ward",                   "category": "Location metadata",      "sensitivity": "Medium", "phi_hipaa": "Indirect",         "notes": "Small wards -> low k, high re-id risk"},
        {"field": "timestamp",              "category": "Temporal metadata",      "sensitivity": "Medium", "phi_hipaa": "Indirect",         "notes": "Precise timing narrows the anonymity set"},
        {"field": "source_ip",              "category": "Network metadata",       "sensitivity": "Medium", "phi_hipaa": "No",               "notes": "Security-relevant; not clinical, but can reveal location/network"},
        {"field": "firmware_version",       "category": "Device metadata",        "sensitivity": "Low",    "phi_hipaa": "No",               "notes": "Security posture indicator, not personal data"},
        {"field": "battery_pct / signal",   "category": "Telemetry metadata",     "sensitivity": "Low",    "phi_hipaa": "No",               "notes": "Operational data only"},
    ])
