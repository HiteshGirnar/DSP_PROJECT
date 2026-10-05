"""
core/data_gen.py
-----------------
Reusable, parameterized synthetic Healthcare-IoT dataset generator.
Used by scripts/generate_data.py (CLI) and by the Streamlit app (interactive).
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta

DEVICE_TYPES = {
    "wearable_ecg":        {"vital": "heart_rate_bpm",     "normal_range": (55, 100)},
    "wearable_spo2":       {"vital": "spo2_pct",           "normal_range": (94, 100)},
    "smart_infusion_pump": {"vital": "infusion_rate_mlhr", "normal_range": (10, 150)},
    "glucose_monitor":     {"vital": "glucose_mgdl",       "normal_range": (70, 180)},
    "smart_thermometer":   {"vital": "body_temp_c",        "normal_range": (36.1, 37.8)},
    "bp_monitor":          {"vital": "systolic_bp_mmhg",   "normal_range": (100, 140)},
}

FIRMWARE_VERSIONS_CURRENT = ["v3.2.1", "v3.2.2", "v3.3.0"]
FIRMWARE_VERSIONS_OLD = ["v2.0.0", "v2.1.4", "v1.9.9"]  # known-vulnerable
HOSPITAL_SUBNETS = ["10.20.1.", "10.20.2.", "10.20.3."]
EXTERNAL_SUSPECT_RANGES = ["185.220.101.", "45.155.204.", "194.61.24."]
WARDS = ["ICU", "General-A", "General-B", "Cardiology", "Pediatrics"]

DEFAULT_ATTACK_COUNTS = {
    "spoofed_vital_reading":   40,
    "brute_force_bursts":      15,   # number of bursts (each burst = 5-12 records)
    "replay_attack":           20,
    "unauthorized_ip_access":  25,
    "dos_target_devices":       6,   # number of devices subjected to a DoS burst
    "firmware_downgrade":      18,
}

LABEL_NAMES = {
    0: "normal",
    1: "spoofed_vital_reading",
    2: "brute_force_auth",
    3: "replay_attack",
    4: "unauthorized_ip_access",
    5: "denial_of_service_burst",
    6: "firmware_downgrade",
}


def _build_devices(devices_per_type, rng):
    devices = []
    device_id_counter = 1000
    for dtype, meta in DEVICE_TYPES.items():
        for _ in range(devices_per_type):
            devices.append({
                "device_id": f"DEV-{device_id_counter}",
                "device_type": dtype,
                "vital_name": meta["vital"],
                "normal_low": meta["normal_range"][0],
                "normal_high": meta["normal_range"][1],
                "patient_id": f"PT-{rng.integers(10000, 99999)}",
                "ward": rng.choice(WARDS),
                "home_subnet": rng.choice(HOSPITAL_SUBNETS),
                "firmware": rng.choice(FIRMWARE_VERSIONS_CURRENT, p=[0.5, 0.3, 0.2]),
            })
            device_id_counter += 1
    return pd.DataFrame(devices)


def _build_normal_telemetry(devices_df, hours, readings_per_hour, start, rng):
    records = []
    rec_id = 1
    for _, dev in devices_df.iterrows():
        ip_last_octet = rng.integers(2, 250)
        device_ip = f"{dev['home_subnet']}{ip_last_octet}"
        battery = rng.uniform(70, 100)
        for h in range(hours):
            for r in range(readings_per_hour):
                ts = start + timedelta(hours=h, minutes=(60 // readings_per_hour) * r)
                battery = max(1, battery - rng.uniform(0.01, 0.05))
                val = rng.uniform(dev["normal_low"], dev["normal_high"])
                records.append({
                    "record_id": rec_id,
                    "timestamp": ts,
                    "device_id": dev["device_id"],
                    "device_type": dev["device_type"],
                    "patient_id": dev["patient_id"],
                    "ward": dev["ward"],
                    "vital_name": dev["vital_name"],
                    "reading_value": round(val, 2),
                    "battery_pct": round(battery, 1),
                    "signal_strength_dbm": round(rng.uniform(-70, -40), 1),
                    "source_ip": device_ip,
                    "auth_status": "success",
                    "firmware_version": dev["firmware"],
                    "request_count_per_min": rng.integers(1, 4),
                    "threat_label": 0,
                })
                rec_id += 1
    return pd.DataFrame(records), rec_id


def generate_dataset(devices_per_type=12, hours=72, readings_per_hour=4,
                      seed=42, attack_counts=None, start=None):
    """
    Returns (telemetry_df, devices_df).
    attack_counts: dict overriding DEFAULT_ATTACK_COUNTS for any subset of keys.
    """
    rng = np.random.default_rng(seed)
    counts = {**DEFAULT_ATTACK_COUNTS, **(attack_counts or {})}
    start = start or datetime(2026, 9, 1, 0, 0, 0)

    devices_df = _build_devices(devices_per_type, rng)
    df, rec_id = _build_normal_telemetry(devices_df, hours, readings_per_hour, start, rng)

    def clamp(n, lo, hi):
        return max(lo, min(n, hi))

    # --- 1. Spoofed vital readings (Tampering) ---
    n = clamp(counts["spoofed_vital_reading"], 0, len(df))
    if n:
        idx = rng.choice(df.index, size=n, replace=False)
        df.loc[idx, "reading_value"] = (df.loc[idx, "reading_value"] * rng.uniform(2.5, 4.0, size=n)).round(2)
        df.loc[idx, "threat_label"] = 1

    # --- 2. Unauthorized external IP access (Elevation of Privilege) ---
    n = clamp(counts["unauthorized_ip_access"], 0, len(df))
    if n:
        idx = rng.choice(df.index, size=n, replace=False)
        for i in idx:
            df.loc[i, "source_ip"] = rng.choice(EXTERNAL_SUSPECT_RANGES) + str(rng.integers(2, 250))
        df.loc[idx, "threat_label"] = 4

    # --- 3. Denial of Service burst ---
    n_dev = clamp(counts["dos_target_devices"], 0, df["device_id"].nunique())
    if n_dev:
        targets = rng.choice(df["device_id"].unique(), size=n_dev, replace=False)
        mask = df["device_id"].isin(targets)
        burst_idx = df[mask].sample(frac=0.05, random_state=seed + 2).index
        df.loc[burst_idx, "request_count_per_min"] = rng.integers(150, 400, size=len(burst_idx))
        df.loc[burst_idx, "threat_label"] = 5

    # --- 4. Firmware downgrade (Tampering) ---
    n = clamp(counts["firmware_downgrade"], 0, len(df))
    if n:
        idx = rng.choice(df.index, size=n, replace=False)
        df.loc[idx, "firmware_version"] = rng.choice(FIRMWARE_VERSIONS_OLD, size=n)
        df.loc[idx, "threat_label"] = 6

    # --- 5. Brute-force auth bursts (Spoofing) - adds NEW rows ---
    n_bursts = clamp(counts["brute_force_bursts"], 0, len(df))
    new_rows = []
    if n_bursts:
        sample_rows = df.sample(n_bursts, random_state=seed + 1)
        for _, base in sample_rows.iterrows():
            n_attempts = int(rng.integers(5, 12))
            for a in range(n_attempts):
                new_rows.append({
                    "record_id": rec_id,
                    "timestamp": base["timestamp"] - timedelta(seconds=int((n_attempts - a) * 4)),
                    "device_id": base["device_id"],
                    "device_type": base["device_type"],
                    "patient_id": base["patient_id"],
                    "ward": base["ward"],
                    "vital_name": base["vital_name"],
                    "reading_value": np.nan,
                    "battery_pct": base["battery_pct"],
                    "signal_strength_dbm": base["signal_strength_dbm"],
                    "source_ip": base["source_ip"],
                    "auth_status": "failed",
                    "firmware_version": base["firmware_version"],
                    "request_count_per_min": int(rng.integers(8, 20)),
                    "threat_label": 2,
                })
                rec_id += 1
    if new_rows:
        df = pd.concat([df, pd.DataFrame(new_rows)], ignore_index=True)

    # --- 6. Replay attacks (Repudiation) - duplicate + shift a past reading ---
    n = clamp(counts["replay_attack"], 0, len(df))
    if n:
        idx = rng.choice(df.index, size=n, replace=False)
        dupes = df.loc[idx].copy()
        dupes["timestamp"] = dupes["timestamp"] + pd.to_timedelta(rng.integers(6, 48, size=n), unit="h")
        dupes["threat_label"] = 3
        dupes["record_id"] = range(rec_id, rec_id + n)
        rec_id += n
        df = pd.concat([df, dupes], ignore_index=True)

    df = df.sort_values("timestamp").reset_index(drop=True)
    df["threat_name"] = df["threat_label"].map(LABEL_NAMES)
    return df, devices_df
