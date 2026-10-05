"""
app/streamlit_app.py
----------------------
Interactive Streamlit dashboard for the Healthcare IoT Security & Privacy
Risk Assessment project.

Run from the project root:
    streamlit run app/streamlit_app.py
"""

import os
import sys
import io

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.data_gen import generate_dataset, DEFAULT_ATTACK_COUNTS, LABEL_NAMES
from core.detection import run_full_detection, device_risk_summary
from core.privacy import k_anonymity_report, data_classification_table

ROOT = os.path.join(os.path.dirname(__file__), "..")
DATA_DIR = os.path.join(ROOT, "data")
DIAGRAMS_DIR = os.path.join(ROOT, "diagrams")
OUTPUTS_DIR = os.path.join(ROOT, "outputs")

st.set_page_config(page_title="Healthcare IoT Security & Privacy Assessment", layout="wide", page_icon="🏥")

# ----------------------------------------------------------------------
# Beginner-friendly welcome banner (collapsed by default, always visible entry point)
# ----------------------------------------------------------------------
with st.expander("🆕  New here? Click to read a 60-second, no-jargon explanation", expanded=False):
    st.markdown("""
**What is this?** A pretend (fake, synthetic) hospital network full of smart
medical devices — heart-rate wearables, IV pumps, glucose sensors, and so on.
No real patients or hospitals are involved anywhere in this tool.

**What did we do?** We hid realistic "attacks" inside the fake data on
purpose (like a fake break-in), then built a detector — part simple rule,
part AI — to try to catch them. We also checked whether a "patient" in this
fake data could be identified just from indirect clues (their ward, their
device, the time of day) even without their name attached.

**Why does that matter?** This is the same kind of check a real hospital's
security team runs before trusting a new device or system near patients.
It answers two questions in plain numbers: *"Would we actually catch a
hacker?"* and *"Could someone figure out who a patient is, even from data
that looks harmless?"*

**What should I do right now?** Just look at the 5 tabs below. Nothing you
click can break anything — every button either shows you a table/chart or
lets you download a file. If you want to change what's being tested, use
the sliders in the left sidebar and click **"🚀 Generate & Run Analysis."**
""")

# ----------------------------------------------------------------------
# Sidebar controls
# ----------------------------------------------------------------------
st.sidebar.title("⚙️ Simulation Controls")
st.sidebar.caption("Not sure what these do? The defaults are already sensible — just click the button below.")

REQUIRED_UPLOAD_COLS = [
    "timestamp", "device_id", "device_type", "patient_id", "ward",
    "reading_value", "battery_pct", "signal_strength_dbm", "source_ip",
    "auth_status", "firmware_version", "request_count_per_min",
]

data_source = st.sidebar.radio(
    "Data source",
    ["Generate new synthetic data", "Upload my own CSV file", "Load existing CSV from /data"],
    index=0,
    help="'Generate new' creates a brand-new fake hospital network right now, using the sliders below. "
         "'Upload my own' lets you pick a CSV file from your own computer. "
         "'Load existing' reuses the CSV file you already made by running generate_data.py in a terminal.",
)

uploaded_file = None
if data_source == "Upload my own CSV file":
    st.sidebar.caption(
        "Your file needs these columns: " + ", ".join(REQUIRED_UPLOAD_COLS) +
        ". An optional `threat_label` column (0 = normal, nonzero = attack) enables accuracy scoring; "
        "without it, every row is treated as unlabeled and the detector still runs, but recall/precision can't be computed."
    )
    uploaded_file = st.sidebar.file_uploader("Choose a CSV file", type=["csv"])

    @st.cache_data(show_spinner=False)
    def _sample_template():
        telemetry_df, _ = generate_dataset(devices_per_type=2, hours=4, seed=1)
        buf = io.StringIO()
        telemetry_df.head(20).to_csv(buf, index=False)
        return buf.getvalue()

    st.sidebar.download_button(
        "📄 Download a sample CSV (to see the expected format)",
        _sample_template(), file_name="sample_telemetry_template.csv", mime="text/csv",
        use_container_width=True,
    )

if data_source == "Generate new synthetic data":
    st.sidebar.subheader("🏭 How big is the fake hospital?")
    devices_per_type = st.sidebar.slider(
        "Devices per type", 4, 30, 12,
        help="How many of each device (wearables, pumps, monitors...) to simulate. More devices = more data, "
             "takes a little longer to generate.",
    )
    hours = st.sidebar.slider(
        "Hours of telemetry", 24, 168, 72, step=24,
        help="How many hours of readings to simulate. 72 hours = 3 days.",
    )
    seed = st.sidebar.number_input(
        "Random seed", value=42, step=1,
        help="A 'recipe number' for the randomness. Keep this the same to reproduce the exact same fake data "
             "again later; change it to get a different random hospital.",
    )

    st.sidebar.subheader("🕵️ How many fake attacks to hide?")
    st.sidebar.caption("Each slider below controls how many of that specific attack we secretly plant in the data.")
    spoofed = st.sidebar.slider(
        "Fake/spoofed vital readings", 0, 200, DEFAULT_ATTACK_COUNTS["spoofed_vital_reading"],
        help="Impossible readings planted on purpose, e.g. a heart rate that suddenly jumps way too high — like someone tampering with the signal.",
    )
    brute = st.sidebar.slider(
        "Password-guessing attempts", 0, 60, DEFAULT_ATTACK_COUNTS["brute_force_bursts"],
        help="Bursts of failed login attempts, like someone repeatedly guessing a device's password.",
    )
    replay = st.sidebar.slider(
        "Replayed (repeated) messages", 0, 100, DEFAULT_ATTACK_COUNTS["replay_attack"],
        help="Old messages resent later, pretending to be new — like replaying a security-camera loop.",
    )
    unauth_ip = st.sidebar.slider(
        "Break-ins from outside the hospital", 0, 150, DEFAULT_ATTACK_COUNTS["unauthorized_ip_access"],
        help="Traffic pretending to be a hospital device but actually coming from an outside, unrecognized network.",
    )
    dos_devices = st.sidebar.slider(
        "Devices flooded with junk traffic", 0, 20, DEFAULT_ATTACK_COUNTS["dos_target_devices"],
        help="How many devices get overwhelmed with a flood of requests (a 'denial of service' attack), like a prank caller jamming a phone line.",
    )
    fw_downgrade = st.sidebar.slider(
        "Devices rolled back to old, unsafe software", 0, 80, DEFAULT_ATTACK_COUNTS["firmware_downgrade"],
        help="A device's software is secretly downgraded to an older version known to have security holes.",
    )

    attack_counts = {
        "spoofed_vital_reading": spoofed,
        "brute_force_bursts": brute,
        "replay_attack": replay,
        "unauthorized_ip_access": unauth_ip,
        "dos_target_devices": dos_devices,
        "firmware_downgrade": fw_downgrade,
    }
else:
    attack_counts = None
    devices_per_type = hours = seed = None  # not used for "Upload" or "Load existing" paths

st.sidebar.subheader("🎯 How sensitive should the detector be?")
dos_threshold = st.sidebar.slider(
    "Traffic-flood alarm threshold (requests/min)", 5, 100, 20,
    help="If a device sends more messages per minute than this, flag it as a possible flood attack. "
         "Lower = more sensitive (catches more, but more false alarms).",
)
zscore_threshold = st.sidebar.slider(
    "'Impossible reading' sensitivity", 2.0, 6.0, 4.0, step=0.5,
    help="How far a reading has to stray from normal before we call it suspicious. Lower = stricter/more sensitive.",
)
contamination = st.sidebar.slider(
    "AI detector's expected 'weirdness' rate", 0.01, 0.10, 0.02, step=0.01,
    help="Tells the AI (Isolation Forest) roughly what fraction of readings to expect are unusual. "
         "Higher = the AI flags more things as suspicious.",
)

run_button = st.sidebar.button("🚀 Generate & Run Analysis", type="primary", use_container_width=True)
st.sidebar.caption("Click this any time after moving a slider to see updated results.")


# ----------------------------------------------------------------------
# Cached pipeline
# ----------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def _generate(devices_per_type, hours, seed, attack_counts):
    telemetry_df, devices_df = generate_dataset(
        devices_per_type=devices_per_type, hours=hours, seed=seed, attack_counts=attack_counts
    )
    return telemetry_df, devices_df


def _load_uploaded(file):
    """Reads an uploaded CSV, validates required columns, and fills in anything
    the detection/privacy pipeline needs but the user's file doesn't have."""
    df = pd.read_csv(file)

    missing = [c for c in REQUIRED_UPLOAD_COLS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Download the sample CSV in the sidebar to see the expected format."
        )

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    n_bad_ts = df["timestamp"].isna().sum()
    if n_bad_ts:
        st.warning(f"{n_bad_ts} row(s) had a timestamp that couldn't be parsed and were dropped.")
        df = df.dropna(subset=["timestamp"])

    if "record_id" not in df.columns:
        df.insert(0, "record_id", range(1, len(df) + 1))

    if "threat_label" not in df.columns:
        st.info("No `threat_label` column found — every row will be treated as unlabeled. "
                 "The detector will still run, but accuracy (precision/recall/F1) can't be scored "
                 "against a ground truth you haven't provided.")
        df["threat_label"] = 0
    df["threat_label"] = pd.to_numeric(df["threat_label"], errors="coerce").fillna(0).astype(int)
    df["threat_name"] = df["threat_label"].map(LABEL_NAMES)
    df["threat_name"] = df["threat_name"].fillna("unknown_label_" + df["threat_label"].astype(str))

    devices_df = (
        df[["device_id", "device_type"]].drop_duplicates().reset_index(drop=True)
        if {"device_id", "device_type"}.issubset(df.columns) else pd.DataFrame(columns=["device_id", "device_type"])
    )
    return df, devices_df


@st.cache_data(show_spinner=False)
def _load_existing():
    telemetry_path = os.path.join(DATA_DIR, "healthcare_iot_telemetry.csv")
    devices_path = os.path.join(DATA_DIR, "device_inventory.csv")
    telemetry_df = pd.read_csv(telemetry_path, parse_dates=["timestamp"])
    devices_df = pd.read_csv(devices_path)
    return telemetry_df, devices_df


@st.cache_data(show_spinner=False)
def _detect(df, dos_threshold, zscore_threshold, contamination):
    return run_full_detection(df, dos_threshold=dos_threshold, zscore_threshold=zscore_threshold, contamination=contamination)


# Initialize / refresh session state
if "telemetry_df" not in st.session_state or run_button:
    if data_source == "Upload my own CSV file" and uploaded_file is None:
        st.info("👆 Upload a CSV file using the control in the sidebar to continue — or switch to "
                "'Generate new synthetic data' if you don't have one yet.")
        st.stop()

    with st.spinner("Loading data and running detection..."):
        if data_source == "Generate new synthetic data":
            telemetry_df, devices_df = _generate(devices_per_type, hours, seed, attack_counts)
        elif data_source == "Upload my own CSV file":
            try:
                telemetry_df, devices_df = _load_uploaded(uploaded_file)
            except ValueError as e:
                st.error(f"Couldn't use that file: {e}")
                st.stop()
            except Exception as e:
                st.error(f"Couldn't read that file as a CSV: {e}")
                st.stop()
        else:
            try:
                telemetry_df, devices_df = _load_existing()
            except FileNotFoundError:
                st.error("No existing CSV found in /data. Run `python scripts/generate_data.py` first, or choose 'Generate new synthetic data'.")
                st.stop()

        df, perf_df, flagged = _detect(telemetry_df, dos_threshold, zscore_threshold, contamination)
        risk_summary = device_risk_summary(df)
        kanon = k_anonymity_report(df)

        st.session_state.update({
            "telemetry_df": telemetry_df, "devices_df": devices_df,
            "df": df, "perf_df": perf_df, "flagged": flagged,
            "risk_summary": risk_summary, "kanon": kanon,
        })

df = st.session_state["df"]
perf_df = st.session_state["perf_df"]
flagged = st.session_state["flagged"]
risk_summary = st.session_state["risk_summary"]
kanon = st.session_state["kanon"]
devices_df = st.session_state["devices_df"]

# ----------------------------------------------------------------------
# Header + KPIs
# ----------------------------------------------------------------------
st.title("🏥 Security and Privacy Risks in Healthcare IoT")
st.caption("A fake hospital network, real attack patterns, and an AI-assisted detector — see the '🆕 New here?' box above if this is your first visit.")

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total readings", f"{len(df):,}", help="How many device messages are in the fake dataset overall.")
k2.metric("Devices simulated", f"{df['device_id'].nunique()}", help="How many separate medical devices are in this fake hospital.")
k3.metric("Real attacks hidden", f"{int((df['threat_label'] != 0).sum())}", help="How many attacks we secretly planted, so we know the 'right answer' to check the detector against.")
k4.metric("Attacks caught", f"{int(df['combined_flag'].sum())}", help="How many events the detector (rules + AI combined) flagged as suspicious.")
combined_row = perf_df[perf_df["detector"] == "combined"].iloc[0]
k5.metric("Catch rate", f"{combined_row['recall']:.0%}", help="Of all the real hidden attacks, what percentage did the detector successfully catch? Higher is better.")

st.divider()

tab_overview, tab_detect, tab_privacy, tab_risk, tab_downloads = st.tabs(
    ["📊 Overview", "🛡️ Threat Detection", "🔐 Privacy Risk", "📋 Risk Register & Recommendations", "📥 Downloads & Diagrams"]
)

# ----------------------------------------------------------------------
# TAB 1: Overview
# ----------------------------------------------------------------------
with tab_overview:
    st.info(
        "💬 **In plain English:** this tab shows the 'big picture' — how many devices we simulated, "
        "what kinds of attacks we hid, and where they landed. Think of it as the summary page.",
        icon="💬",
    )
    col1, col2 = st.columns(2)
    with col1:
        counts = df["threat_name"].value_counts().drop("normal", errors="ignore").reset_index()
        counts.columns = ["threat_name", "count"]
        fig = px.bar(counts.sort_values("count"), x="count", y="threat_name", orientation="h",
                     title="Injected Threat Events by Type (Ground Truth)", color_discrete_sequence=["#c0392b"])
        st.plotly_chart(fig, use_container_width=True)
        st.caption("👆 Each bar = how many of that specific fake attack we planted in the data.")
    with col2:
        fig2 = px.bar(risk_summary.sort_values("flag_rate_pct"), x="flag_rate_pct", y="device_type", orientation="h",
                      title="Flagged-Event Rate (%) by Device Type", color_discrete_sequence=["#2980b9"])
        st.plotly_chart(fig2, use_container_width=True)
        st.caption("👆 Which device types had the most suspicious activity, as a percentage of their traffic.")

    fig3 = px.histogram(df, x="request_count_per_min", nbins=40, title="Request Rate per Minute (all devices)")
    fig3.add_vline(x=dos_threshold, line_dash="dash", line_color="red",
                   annotation_text=f"DoS rule threshold ({dos_threshold}/min)")
    st.plotly_chart(fig3, use_container_width=True)
    st.caption("👆 Most devices send only a handful of messages per minute (the tall bar near zero). "
               "Anything past the red dashed line is treated as a possible traffic-flood attack.")

    st.subheader("Device fleet")
    st.caption("Every simulated device in this fake hospital — its type, patient, ward, and network info.")
    st.dataframe(devices_df, use_container_width=True, height=250)

# ----------------------------------------------------------------------
# TAB 2: Threat Detection
# ----------------------------------------------------------------------
with tab_detect:
    st.info(
        "💬 **In plain English:** here's the scoreboard for our two detectors — 'Rule-based' (simple, "
        "hand-written alarms) and 'Isolation Forest' (an AI that spots anything statistically weird). "
        "'Combined' uses both together. Look at **Recall** = % of real attacks actually caught, and "
        "**Precision** = of everything flagged, what % was a real attack (vs. a false alarm).",
        icon="💬",
    )
    st.subheader("Detector performance vs. ground truth")
    st.dataframe(perf_df, use_container_width=True)
    st.caption(
        "Rule-based detection catches known attack signatures with high precision. "
        "Isolation Forest (unsupervised ML) is retained to catch novel anomalies with no existing signature, "
        "at the cost of more false positives."
    )

    st.subheader("Flagged events")
    st.caption("Every individual reading the detector considered suspicious. Use the filters below to narrow it down.")
    c1, c2, c3 = st.columns(3)
    device_filter = c1.multiselect("Device type", sorted(df["device_type"].unique()))
    threat_filter = c2.multiselect("Threat type", sorted(flagged["threat_name"].unique()))
    detector_filter = c3.multiselect("Detected by", sorted(flagged["detected_by"].unique()))

    view = flagged.copy()
    if device_filter:
        view = view[view["device_type"].isin(device_filter)]
    if threat_filter:
        view = view[view["threat_name"].isin(threat_filter)]
    if detector_filter:
        view = view[view["detected_by"].isin(detector_filter)]

    st.dataframe(view, use_container_width=True, height=350)
    st.caption(f"Showing {len(view):,} of {len(flagged):,} flagged events")

    st.subheader("Device-level risk summary")
    st.dataframe(risk_summary, use_container_width=True)

# ----------------------------------------------------------------------
# TAB 3: Privacy Risk
# ----------------------------------------------------------------------
with tab_privacy:
    st.info(
        "💬 **In plain English:** even if you strip a patient's name off their data, sometimes a few "
        "'harmless' details (like their ward + which device + roughly what time) are enough to figure out "
        "who they are anyway. This tab measures exactly how big that risk is.",
        icon="💬",
    )
    st.subheader("Data sensitivity classification")
    st.caption("Which fields in our data are risky (High), somewhat risky (Medium), or harmless (Low) if leaked.")
    st.dataframe(data_classification_table(), use_container_width=True)

    st.subheader("k-Anonymity re-identification risk")
    st.caption(
        "We grouped every reading by ward + device type + hour-of-day, then counted how many different "
        "patients shared each group. If only 1-2 patients share a group, anyone who knows those 3 details "
        "can almost pinpoint who it is — that's a LOW 'k' number, which means HIGH risk."
    )

    risk_counts = kanon["risk_level"].value_counts().reindex(
        ["CRITICAL (k<=2)", "HIGH (k<=5)", "MODERATE (k<=10)", "LOW (k>10)"]
    ).fillna(0).reset_index()
    risk_counts.columns = ["risk_level", "groups"]
    fig4 = px.bar(risk_counts, x="risk_level", y="groups", color="risk_level",
                  title="Quasi-identifier groups by re-identification risk level",
                  color_discrete_map={
                      "CRITICAL (k<=2)": "#b02a2a", "HIGH (k<=5)": "#d97706",
                      "MODERATE (k<=10)": "#eab308", "LOW (k>10)": "#16a34a",
                  })
    st.plotly_chart(fig4, use_container_width=True)

    critical_pct = (kanon["k_distinct_patients"] <= 5).mean() * 100
    st.warning(
        f"🚨 **{critical_pct:.0f}% of ward/device/time combinations could narrow a patient down to 5 people "
        f"or fewer** — just from indirect details, with no name attached. This is the project's single "
        f"biggest privacy finding: 'anonymous' hospital metadata often isn't as anonymous as it looks."
    )

    st.caption("Full breakdown below — each row is one ward+device+hour combination and how many patients shared it (k).")

    st.dataframe(kanon, use_container_width=True, height=300)

# ----------------------------------------------------------------------
# TAB 4: Risk Register & Recommendations
# ----------------------------------------------------------------------
with tab_risk:
    st.info(
        "💬 **In plain English:** this tab turns everything into a to-do list. First, a reference table of "
        "the 6 classic ways an attacker can misbehave (STRIDE). Then, our specific risks ranked by how "
        "worried you should be. Then, what to actually do about them.",
        icon="💬",
    )
    st.subheader("STRIDE threat categories")
    st.caption("A standard checklist security experts use to make sure no type of attack gets overlooked.")
    stride_df = pd.DataFrame([
        {"STRIDE category": "Spoofing", "Example threat": "Attacker impersonates a device via brute-forced/default credentials", "Primary control": "Unique per-device certs/keys; account lockout; mutual TLS"},
        {"STRIDE category": "Tampering", "Example threat": "Vital-sign values altered in transit, or firmware rolled back", "Primary control": "Message integrity (HMAC/signing); signed firmware; anti-rollback"},
        {"STRIDE category": "Repudiation", "Example threat": "A replayed/duplicated reading is indistinguishable from a new one", "Primary control": "Sequence numbers/nonces; timestamp validation; audit logging"},
        {"STRIDE category": "Information Disclosure", "Example threat": "PHI-bearing telemetry intercepted over an unencrypted link", "Primary control": "TLS/DTLS everywhere; encryption at rest; strict access control"},
        {"STRIDE category": "Denial of Service", "Example threat": "A device or attacker floods the gateway/cloud with requests", "Primary control": "Rate limiting; anomaly-based throttling; segmentation"},
        {"STRIDE category": "Elevation of Privilege", "Example threat": "Traffic from an unauthorized IP is accepted as a trusted device", "Primary control": "Network allow-listing; zero-trust auth; least privilege"},
    ])
    st.dataframe(stride_df, use_container_width=True)

    st.subheader("Consolidated risk register")
    st.caption("Our specific findings, ranked. 'Critical' = fix this first.")
    risk_register = pd.DataFrame([
        {"#": "R1", "Risk": "Re-identification via ward/device/time metadata correlation", "Likelihood": "High", "Impact": "High", "Priority": "Critical"},
        {"#": "R2", "Risk": "Tampered/spoofed vital-sign readings → incorrect clinical decisions", "Likelihood": "Medium", "Impact": "High", "Priority": "Critical"},
        {"#": "R3", "Risk": "Infusion pump command injection / firmware rollback → incorrect dosing", "Likelihood": "Low-Medium", "Impact": "Very High", "Priority": "Critical"},
        {"#": "R4", "Risk": "Brute-force / credential-reuse against device authentication", "Likelihood": "High", "Impact": "Medium", "Priority": "High"},
        {"#": "R5", "Risk": "Unauthorized external network access accepted as trusted device", "Likelihood": "Medium", "Impact": "High", "Priority": "High"},
        {"#": "R6", "Risk": "DoS floods disrupting telemetry availability", "Likelihood": "Medium", "Impact": "Medium", "Priority": "Medium"},
        {"#": "R7", "Risk": "Replay of old readings masking deterioration or an attack", "Likelihood": "Low", "Impact": "Medium", "Priority": "Medium"},
        {"#": "R8", "Risk": "Insider misuse of legitimate credentials on high-consequence devices", "Likelihood": "Low", "Impact": "High", "Priority": "Medium-High"},
    ])
    st.dataframe(risk_register, use_container_width=True)

    st.subheader("Recommendations")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Technical controls**")
        st.markdown("""
- Encrypt all device↔gateway↔cloud traffic (TLS/DTLS, mutual certificates)
- Unique per-device credentials; account lockout; rate-limit auth attempts (R4)
- Signed firmware with anti-rollback protection (R2, R3)
- Sequence numbers/timestamps to reject replayed packets (R7)
- Network allow-listing by hospital subnet (R5)
- Layer rule-based detection (precise) with ML anomaly detection (catches novel attacks)
- Rate limiting / anomaly-based throttling at the gateway (R6)
""")
    with col2:
        st.markdown("**Privacy / governance controls**")
        st.markdown("""
- Treat ward + device type + timestamp as quasi-identifiers requiring PHI-level access control (R1)
- Generalize timestamps (shift-level, not exact) and suppress ward detail for small wards
- Apply data minimization: forward only fields a downstream consumer needs
- Maintain immutable audit logs of telemetry/identity store access
- Require dual authorization for dosing-relevant configuration changes (R3, R8)
""")

# ----------------------------------------------------------------------
# TAB 5: Downloads & Diagrams
# ----------------------------------------------------------------------
with tab_downloads:
    st.info(
        "💬 **In plain English:** grab any table on this dashboard as a spreadsheet file, the security "
        "diagrams (open them at app.diagrams.net), or the full written report — to keep, share, or open "
        "in Excel/Word.",
        icon="💬",
    )
    st.subheader("Export current results")

    def df_download(label, dataframe, filename):
        buf = io.StringIO()
        dataframe.to_csv(buf, index=False)
        st.download_button(label, buf.getvalue(), file_name=filename, mime="text/csv")

    c1, c2, c3 = st.columns(3)
    with c1:
        df_download("⬇️ Flagged threats CSV", flagged, "flagged_threats.csv")
        df_download("⬇️ Device risk summary CSV", risk_summary, "device_risk_summary.csv")
    with c2:
        df_download("⬇️ Detection performance CSV", perf_df, "detection_performance.csv")
        df_download("⬇️ k-Anonymity report CSV", kanon, "k_anonymity_report.csv")
    with c3:
        df_download("⬇️ Full telemetry CSV", df, "healthcare_iot_telemetry.csv")
        df_download("⬇️ Device inventory CSV", devices_df, "device_inventory.csv")

    st.divider()
    st.subheader("Threat model diagrams (Draw.io)")
    st.caption("Download and open at https://app.diagrams.net or in the Draw.io desktop app.")

    for fname, label in [
        ("dfd_stride_threat_model.drawio", "⬇️ DFD + STRIDE threat model (.drawio)"),
        ("attack_tree_infusion_pump.drawio", "⬇️ Attack tree: infusion pump compromise (.drawio)"),
    ]:
        fpath = os.path.join(DIAGRAMS_DIR, fname)
        if os.path.exists(fpath):
            with open(fpath, "rb") as f:
                st.download_button(label, f.read(), file_name=fname, mime="application/xml")
        else:
            st.info(f"{fname} not found in /diagrams")

    st.divider()
    st.subheader("Full Word report")
    report_path = os.path.join(OUTPUTS_DIR, "Healthcare_IoT_Threat_Privacy_Assessment.docx")
    if os.path.exists(report_path):
        with open(report_path, "rb") as f:
            st.download_button("⬇️ Healthcare_IoT_Threat_Privacy_Assessment.docx", f.read(),
                                file_name="Healthcare_IoT_Threat_Privacy_Assessment.docx",
                                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    else:
        st.info("Report not found in /outputs. Build it with `node scripts/build_report.js` (see README).")
