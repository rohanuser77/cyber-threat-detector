"""
CyberShield AI — SOC Dashboard (Iteration 1 Redesign)
NTRO PS #26145 | AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Design goal: A beginner can open this and understand within 5 seconds:
  1. What kind of traffic is entering the system?
  2. Is the traffic normal or suspicious?
  3. What did the AI detect, and why?
"""

import sys
import json
import time
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

import streamlit as st
import plotly.graph_objects as go

# ── Project root on path ─────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.stream_simulator import run_stream_simulator

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield AI — NTRO PS #26145",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Paths ─────────────────────────────────────────────────────────────────────
PIPELINE_DIR = PROJECT_ROOT / "pipeline"
SUMMARY_FILE = PIPELINE_DIR / "run_summary.json"
ALERTS_FILE  = PIPELINE_DIR / "alerts.jsonl"
MODELS_DIR   = PROJECT_ROOT / "model"
FLOWS_CSV    = PROJECT_ROOT / "data" / "processed" / "flows.csv"

ATTACK_OPTIONS = {
    "ddos":             ("DDoS Flood",           "Too much traffic arriving at once — like thousands of people hitting a door at the same time."),
    "port_scan":        ("Port Scan",             "Someone is quietly checking many doors on the network, looking for an unlocked one."),
    "botnet_beacon":    ("Botnet Beaconing",      "A device is making the same connection repeatedly on a fixed schedule — typical of malware checking in with a controller."),
    "dga_dns":          ("DNS Tunnelling",         "Unusual DNS queries that hide data inside legitimate-looking domain lookups."),
    "encrypted_malware":("Encrypted Malware",     "Suspicious patterns in encrypted traffic metadata — no decryption needed to spot anomalies."),
    "exfiltration":     ("Data Exfiltration",     "An unusually large amount of data is leaving the network — a sign that files may be being stolen."),
}

THREAT_PLAIN_ENGLISH = {
    "ddos":             "massive flood of packets from many sources",
    "port_scan":        "rapid scanning of many destination ports",
    "botnet_beacon":    "highly periodic heartbeat to an external server",
    "dga_dns":          "algorithmically-generated DNS names with high character randomness",
    "encrypted_malware":"unusual burst patterns in encrypted TLS/QUIC metadata",
    "exfiltration":     "severely outbound-skewed byte transfer ratio",
}

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ---- Base ---- */
html, body, [class*="css"] {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
.stApp { background: #0b1120; }
section[data-testid="stSidebar"] { display: none; }

/* ---- Top bar ---- */
.topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 32px 10px 32px;
    border-bottom: 1px solid #1b2a45;
    margin-bottom: 0;
}
.topbar-logo {
    font-size: 1.25rem; font-weight: 800; color: #e6edf3;
    display: flex; align-items: center; gap: 10px;
}
.topbar-sub { font-size: 0.73rem; color: #6e8ba8; margin-top: 1px; }
.status-pill {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 5px 14px; border-radius: 20px;
    font-size: 0.76rem; font-weight: 700; letter-spacing: 0.04em;
}
.pill-ready  { background: rgba(82,196,26,.12); color: #52c41a; border: 1px solid #52c41a55; }
.pill-run    { background: rgba(0,194,203,.12);  color: #00c2cb; border: 1px solid #00c2cb55; }
.pill-done   { background: rgba(82,196,26,.12); color: #52c41a; border: 1px solid #52c41a55; }
.pill-attack { background: rgba(255,75,75,.12);  color: #ff4b4b; border: 1px solid #ff4b4b55; }

/* ---- Hero ---- */
.hero {
    text-align: center;
    padding: 54px 24px 36px 24px;
}
.hero h1 {
    font-size: 2.6rem; font-weight: 800; color: #e6edf3;
    letter-spacing: -0.03em; margin: 0 0 10px 0;
}
.hero p {
    font-size: 1.08rem; color: #8b9ab5; max-width: 600px;
    margin: 0 auto 36px auto; line-height: 1.6;
}

/* ---- Scenario cards ---- */
.scenario-row {
    display: flex; gap: 20px;
    max-width: 880px; margin: 0 auto;
}
.scenario-card {
    flex: 1; padding: 30px 28px; border-radius: 14px;
    border: 1px solid; position: relative; overflow: hidden;
    transition: transform .2s;
}
.scenario-card:hover { transform: translateY(-3px); }
.card-normal {
    background: linear-gradient(135deg, #0d2033 0%, #0b1a2e 100%);
    border-color: #1c4070;
}
.card-attack {
    background: linear-gradient(135deg, #200e10 0%, #180b0e 100%);
    border-color: #5c1a1a;
}
.card-icon { font-size: 2rem; margin-bottom: 14px; }
.card-title { font-size: 1.15rem; font-weight: 700; color: #e6edf3; margin-bottom: 8px; }
.card-desc  { font-size: 0.87rem; color: #7a8fa8; line-height: 1.55; margin-bottom: 20px; }

/* ---- Result blocks ---- */
.result-box {
    border-radius: 12px; padding: 26px 28px; margin: 0 auto;
    max-width: 860px;
}
.result-normal { background: #0d2033; border: 1px solid #1c4070; }
.result-attack { background: #200e10; border: 1px solid #5c1a1a; }
.result-title  { font-size: 1.3rem; font-weight: 800; margin-bottom: 6px; }
.result-subtitle { font-size: 0.9rem; color: #8b9ab5; line-height: 1.55; }

/* ---- Stats row ---- */
.stat-row { display: flex; gap: 14px; margin: 22px 0 0 0; flex-wrap: wrap; }
.stat-box {
    flex: 1; min-width: 120px;
    background: rgba(255,255,255,.04);
    border: 1px solid #1e3050; border-radius: 10px;
    padding: 14px 18px;
}
.stat-label { font-size: 0.74rem; color: #6e8ba8; text-transform: uppercase;
              letter-spacing: .06em; margin-bottom: 4px; }
.stat-value { font-size: 1.6rem; font-weight: 800; color: #e6edf3; }
.stat-unit  { font-size: 0.72rem; color: #4a6080; }

/* ---- Alert row ---- */
.alert-item {
    display: flex; align-items: flex-start; gap: 16px;
    padding: 14px 18px; border-radius: 10px; margin-bottom: 8px;
    background: rgba(255,255,255,.03); border: 1px solid #1b2a45;
}
.alert-dot { width: 10px; height: 10px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }
.dot-high   { background: #ff4b4b; box-shadow: 0 0 6px #ff4b4b88; }
.dot-medium { background: #ffa940; }
.dot-low    { background: #ffd666; }
.alert-threat  { font-size: 0.9rem; font-weight: 700; color: #e6edf3; }
.alert-detail  { font-size: 0.8rem; color: #7a8fa8; margin-top: 2px; }
.alert-badge {
    margin-left: auto; padding: 3px 10px; border-radius: 20px;
    font-size: 0.72rem; font-weight: 700;
}
.badge-High   { background: rgba(255,75,75,.15); color: #ff4b4b; }
.badge-Medium { background: rgba(255,169,64,.15); color: #ffa940; }
.badge-Low    { background: rgba(255,214,102,.15); color: #ffd666; }

/* ---- Progress ---- */
.progress-label { font-size: 0.85rem; color: #6e8ba8; text-align: center; margin-top: 10px; }

/* ---- Section heading ---- */
.section-heading {
    font-size: 1rem; font-weight: 700; color: #8b9ab5;
    text-transform: uppercase; letter-spacing: .08em;
    margin: 28px 0 12px 0; max-width: 860px; margin-left: auto; margin-right: auto;
}

/* ---- Buttons override ---- */
.stButton > button {
    width: 100%; font-weight: 700; border-radius: 9px;
    padding: 12px 20px; font-size: 0.95rem; letter-spacing: .02em;
    transition: opacity .2s;
}
.stButton > button:hover { opacity: 0.85; }

/* Streamlit block spacing */
div.block-container { padding: 0 !important; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_summary() -> Dict[str, Any]:
    """Load the latest run summary, returning safe defaults if missing."""
    defaults = {
        "scenario": None,
        "replay_status": "IDLE",
        "total_flows_processed": 0,
        "normal_flows_count": 0,
        "suspicious_flows_count": 0,
        "total_alerts": 0,
        "elapsed_time_sec": 0.0,
        "measured_throughput_flows_per_sec": 0.0,
        "avg_confidence_score": 0.0,
        "severity_breakdown": {"Low": 0, "Medium": 0, "High": 0},
        "threat_class_counts": {},
    }
    if not SUMMARY_FILE.exists():
        return defaults
    try:
        with open(SUMMARY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        defaults.update(data)
        return defaults
    except Exception:
        return defaults


def load_alerts(max_n: int = 50) -> List[Dict[str, Any]]:
    """Load the latest N alerts newest-first."""
    if not ALERTS_FILE.exists():
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        alerts = []
        for line in reversed(lines[-max_n:]):
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    pass
        return alerts
    except Exception:
        return []


def explain_normal(summary: Dict[str, Any]) -> str:
    n   = summary["total_flows_processed"]
    nm  = summary["normal_flows_count"]
    sus = summary["suspicious_flows_count"]
    if sus == 0:
        return (
            f"The AI analyzed {n:,} network flows. "
            f"Every single one was classified as normal, safe activity. "
            "No suspicious behavior was detected above the alert threshold — "
            "this is exactly what you want to see in a healthy network."
        )
    pct = sus / n * 100 if n else 0
    return (
        f"The AI analyzed {n:,} network flows and flagged {sus} ({pct:.1f}%) as suspicious. "
        f"{nm:,} flows were classified as normal. "
        "Even normal traffic datasets can contain a small number of edge-case flows "
        "that statistically resemble attack patterns. These are shown honestly below."
    )


def explain_attack(summary: Dict[str, Any], attack_key: str) -> str:
    sus  = summary["suspicious_flows_count"]
    n    = summary["total_flows_processed"]
    conf = summary["avg_confidence_score"] * 100
    what = THREAT_PLAIN_ENGLISH.get(attack_key, "unusual network behavior")
    if sus == 0:
        return (
            f"The AI processed {n:,} flows filtered for '{attack_key}' traffic "
            "but did not generate alerts above the configured confidence threshold. "
            "This may indicate the filtered records were ambiguous or borderline patterns."
        )
    return (
        f"The AI detected {sus} suspicious flow{'s' if sus > 1 else ''} out of {n:,} processed. "
        f"The key indicator was: **{what}**. "
        f"The average detection confidence was {conf:.1f}%, "
        "meaning the model was highly certain about its classification. "
        "Technical evidence for each alert is expandable below."
    )


def render_stat(label: str, value: str, unit: str = "") -> str:
    return f"""
    <div class="stat-box">
        <div class="stat-label">{label}</div>
        <div class="stat-value">{value}</div>
        <div class="stat-unit">{unit}</div>
    </div>"""


def render_alert_item(alert: Dict[str, Any]) -> str:
    sev   = alert.get("severity", "Low")
    cls   = alert.get("threat_class", "unknown").replace("_", " ").title()
    conf  = alert.get("confidence_score", 0.0)
    src   = alert.get("src_ip", "-")
    dst   = f"{alert.get('dst_ip','-')}:{alert.get('dst_port','-')}"
    dot_c = {"High": "dot-high", "Medium": "dot-medium", "Low": "dot-low"}.get(sev, "dot-low")
    ev    = alert.get("evidence", {})
    ev_str = " · ".join(f"{k}: {v}" for k, v in list(ev.items())[:3])
    return f"""
    <div class="alert-item">
        <div class="alert-dot {dot_c}"></div>
        <div style="flex:1">
            <div class="alert-threat">{cls}</div>
            <div class="alert-detail">From {src} → {dst} &nbsp;|&nbsp; Confidence: {conf*100:.1f}%</div>
            <div class="alert-detail" style="color:#4a6080;margin-top:4px;">{ev_str}</div>
        </div>
        <span class="alert-badge badge-{sev}">{sev.upper()}</span>
    </div>"""


def run_test(scenario_key: str, filter_label: Optional[str], max_records: int = 1000) -> Dict[str, Any]:
    """Run the actual pipeline and return the resulting summary."""
    return run_stream_simulator(
        csv_path=FLOWS_CSV,
        model_dir=MODELS_DIR,
        output_dir=PIPELINE_DIR,
        batch_size=150,
        batch_delay_sec=0.0,      # no artificial delay inside Streamlit
        max_records=max_records,
        reset_alerts=True,
        filter_label=filter_label,
        scenario_name=scenario_key,
    )


# ── Session state keys ────────────────────────────────────────────────────────
if "last_scenario"  not in st.session_state: st.session_state.last_scenario  = None
if "result_summary" not in st.session_state: st.session_state.result_summary = None
if "result_alerts"  not in st.session_state: st.session_state.result_alerts  = []
if "attack_key"     not in st.session_state: st.session_state.attack_key     = "port_scan"


# ── TOP BAR ───────────────────────────────────────────────────────────────────
summary = load_summary()
status  = summary.get("replay_status", "IDLE")

if status == "RUNNING":
    pill_cls = "pill-run";    pill_txt = "⚡ Processing Traffic…"
elif status == "COMPLETED" and st.session_state.last_scenario:
    scn = st.session_state.last_scenario
    if scn == "normal_traffic":
        pill_cls = "pill-done";   pill_txt = "🟢 Normal Traffic Test Done"
    else:
        pill_cls = "pill-attack"; pill_txt = "🔴 Attack Simulation Done"
else:
    pill_cls = "pill-ready"; pill_txt = "🟢 System Ready — Waiting for Traffic Test"

st.markdown(f"""
<div class="topbar">
    <div>
        <div class="topbar-logo">🛡️ CyberShield AI</div>
        <div class="topbar-sub">NTRO PS #26145 · Passive Unidirectional Network Threat Detection</div>
    </div>
    <span class="status-pill {pill_cls}">{pill_txt}</span>
</div>
""", unsafe_allow_html=True)


# ══ IDLE STATE — Welcome screen ════════════════════════════════════════════════
if st.session_state.last_scenario is None:
    st.markdown("""
    <div class="hero">
        <h1>Understand your network.<br>Detect threats. Stay informed.</h1>
        <p>CyberShield AI watches network traffic without interfering with it.
           It uses AI to identify unusual activity and explain what might be happening —
           in plain English.</p>
    </div>
    """, unsafe_allow_html=True)

    # Scenario cards via columns (Streamlit buttons can't live inside raw HTML)
    col_l, col_r = st.columns(2, gap="large")

    with col_l:
        st.markdown("""
        <div class="scenario-card card-normal">
            <div class="card-icon">🟢</div>
            <div class="card-title">Test Normal Traffic</div>
            <div class="card-desc">See how AI analyzes safe, everyday network activity —
            browsing, file transfers, and DNS lookups — and confirms it is not suspicious.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("▶ Test Normal Traffic", key="btn_normal", use_container_width=True):
            st.session_state.last_scenario = "normal_traffic"
            st.rerun()

    with col_r:
        st.markdown("""
        <div class="scenario-card card-attack">
            <div class="card-icon">⚠️</div>
            <div class="card-title">Simulate a Cyber Attack</div>
            <div class="card-desc">Run a safe, pre-generated attack scenario and watch
            the AI identify suspicious behavior, explain why, and issue alerts.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("⚠ Simulate Cyber Attack", key="btn_attack", use_container_width=True):
            st.session_state.last_scenario = "attack_setup"
            st.rerun()

    st.stop()


# ══ ATTACK SETUP — pick scenario ══════════════════════════════════════════════
if st.session_state.last_scenario == "attack_setup":
    st.markdown("""
    <div class="hero" style="padding-bottom:20px;">
        <h1 style="font-size:2rem;">Choose an Attack Scenario</h1>
        <p>Select the type of threat you want to demonstrate.
           The AI will process real simulated network flows for that attack category.</p>
    </div>
    """, unsafe_allow_html=True)

    _, mid, _ = st.columns([1, 3, 1])
    with mid:
        labels = {k: f"{v[0]} — {v[1]}" for k, v in ATTACK_OPTIONS.items()}
        choice = st.radio(
            "Attack type",
            options=list(ATTACK_OPTIONS.keys()),
            format_func=lambda k: f"{ATTACK_OPTIONS[k][0]}",
            index=list(ATTACK_OPTIONS.keys()).index(st.session_state.attack_key),
            label_visibility="collapsed"
        )
        st.session_state.attack_key = choice
        _, name, desc = choice, ATTACK_OPTIONS[choice][0], ATTACK_OPTIONS[choice][1]
        st.info(f"**{name}** — {desc}")
        st.markdown("<br>", unsafe_allow_html=True)

        col_go, col_back = st.columns([2, 1])
        with col_go:
            if st.button(f"⚠ Simulate {ATTACK_OPTIONS[choice][0]}", use_container_width=True, type="primary"):
                st.session_state.last_scenario = f"attack_{choice}"
                st.rerun()
        with col_back:
            if st.button("← Back", use_container_width=True):
                st.session_state.last_scenario = None
                st.rerun()

    st.stop()


# ══ RUNNING A TEST ════════════════════════════════════════════════════════════
scenario = st.session_state.last_scenario
is_normal_test = (scenario == "normal_traffic")
is_attack_test = scenario.startswith("attack_") and scenario not in ("attack_setup",)
attack_key     = scenario.replace("attack_", "") if is_attack_test else None

if st.session_state.result_summary is None:
    # Not yet run — execute the pipeline now
    if is_normal_test:
        label_txt = "Testing Normal Traffic"
        filter_lbl = "normal"
    else:
        label_txt = f"Simulating {ATTACK_OPTIONS[attack_key][0]}"
        filter_lbl = attack_key

    progress_placeholder = st.empty()
    progress_placeholder.markdown(f"""
    <div style="text-align:center; padding:60px 24px;">
        <div style="font-size:2.5rem;">⚙️</div>
        <div style="font-size:1.2rem; font-weight:700; color:#e6edf3; margin:16px 0 8px;">
            {label_txt}…
        </div>
        <div style="font-size:0.9rem; color:#6e8ba8;">
            The AI is processing network flows. This takes a few seconds.
        </div>
    </div>
    """, unsafe_allow_html=True)

    result = run_test(
        scenario_key=scenario,
        filter_label=filter_lbl,
        max_records=1200
    )

    st.session_state.result_summary = result
    st.session_state.result_alerts  = load_alerts(max_n=80)
    progress_placeholder.empty()
    st.rerun()
    st.stop()


# ══ RESULTS SCREEN ════════════════════════════════════════════════════════════
result  = st.session_state.result_summary
alerts  = st.session_state.result_alerts

n_flows = result.get("total_flows_processed", 0)
n_norm  = result.get("normal_flows_count", 0)
n_sus   = result.get("suspicious_flows_count", 0)
elapsed = result.get("elapsed_time_sec", 0.0)
throughput = result.get("measured_throughput_flows_per_sec", 0.0)
sev_counts = result.get("severity_breakdown", {"Low":0,"Medium":0,"High":0})

_, center, _ = st.columns([1, 4, 1])
with center:

    # ── Result title block ────────────────────────────────────────────────────
    if is_normal_test:
        if n_sus == 0:
            icon, color, title = "🟢", "#52c41a", "All Clear — No Threats Detected"
        else:
            icon, color, title = "🟡", "#ffa940", f"Normal Traffic Test Complete ({n_sus} Borderline Flows)"
        box_cls = "result-normal"
        expl    = explain_normal(result)
    else:
        if n_sus > 0:
            icon, color, title = "🔴", "#ff4b4b", f"Suspicious Activity Detected — {ATTACK_OPTIONS[attack_key][0]}"
        else:
            icon, color, title = "🟡", "#ffa940", "Simulation Complete — No Alerts Triggered"
        box_cls = "result-attack"
        expl    = explain_attack(result, attack_key)

    st.markdown(f"""
    <div class="result-box {box_cls}">
        <div class="result-title" style="color:{color};">{icon} {title}</div>
        <div class="result-subtitle" style="margin-top:10px;">{expl}</div>
        <div class="stat-row">
            {render_stat("Flows Analyzed", f"{n_flows:,}")}
            {render_stat("Normal Flows", f"{n_norm:,}")}
            {render_stat("Suspicious Flags", f"{n_sus:,}")}
            {render_stat("Time Taken", f"{elapsed:.2f}", "seconds")}
            {render_stat("Processing Speed", f"{throughput:,.0f}", "flows / sec")}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Severity mini-bar ─────────────────────────────────────────────────────
    if n_sus > 0:
        st.markdown("<div class='section-heading'>Alert Severity Breakdown</div>", unsafe_allow_html=True)
        fig = go.Figure()
        sev_order = ["High", "Medium", "Low"]
        sev_colors = {"High": "#ff4b4b", "Medium": "#ffa940", "Low": "#ffd666"}
        for s in sev_order:
            fig.add_trace(go.Bar(
                name=s,
                x=[s],
                y=[sev_counts.get(s, 0)],
                marker_color=sev_colors[s],
                text=[sev_counts.get(s, 0)],
                textposition="outside",
                width=0.4,
            ))
        fig.update_layout(
            height=220,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            margin=dict(l=10, r=10, t=10, b=10),
            font=dict(color="#8b9ab5", size=13),
            xaxis=dict(gridcolor="rgba(0,0,0,0)"),
            yaxis=dict(gridcolor="#1b2a45"),
            bargap=0.5,
        )
        st.plotly_chart(fig, use_container_width=True)

    # ── Alert list ────────────────────────────────────────────────────────────
    if alerts:
        st.markdown("<div class='section-heading'>Recent Alerts</div>", unsafe_allow_html=True)
        alert_html = "".join(render_alert_item(a) for a in alerts[:15])
        st.markdown(alert_html, unsafe_allow_html=True)

        if len(alerts) > 15:
            with st.expander(f"Show all {len(alerts)} alerts"):
                more_html = "".join(render_alert_item(a) for a in alerts[15:])
                st.markdown(more_html, unsafe_allow_html=True)
    elif n_sus == 0:
        st.markdown("""
        <div style="text-align:center; padding:30px; color:#4a6080; font-size:0.9rem;">
            No alerts were generated — the AI classified all flows as safe.
        </div>
        """, unsafe_allow_html=True)

    # ── Technical expander ────────────────────────────────────────────────────
    with st.expander("🔬 View Technical Details (for judges & developers)"):
        st.markdown("**Raw Run Summary**")
        st.json({k: v for k, v in result.items()
                 if k not in ("scenario", "target_label_filter", "dataset_source")})
        st.markdown("**Threat Category Counts**")
        tcc = result.get("threat_class_counts", {})
        if tcc:
            st.dataframe(
                {"Threat Class": list(tcc.keys()), "Alert Count": list(tcc.values())},
                use_container_width=True, hide_index=True
            )
        else:
            st.caption("No threat categories recorded.")
        st.caption(
            "All detections are based on packet flow **metadata only**. "
            "No payload decryption is performed. The model uses Shannon entropy, "
            "port fan-out, inter-arrival variance, byte ratios, and DNS query statistics."
        )

    # ── Reset / run another ───────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        if st.button("🔁 Run Normal Traffic Test", use_container_width=True):
            st.session_state.last_scenario  = "normal_traffic"
            st.session_state.result_summary = None
            st.session_state.result_alerts  = []
            st.rerun()
    with col_b:
        if st.button("⚠ Run Attack Simulation", use_container_width=True):
            st.session_state.last_scenario  = "attack_setup"
            st.session_state.result_summary = None
            st.session_state.result_alerts  = []
            st.rerun()
    with col_c:
        if st.button("🏠 Back to Home", use_container_width=True):
            st.session_state.last_scenario  = None
            st.session_state.result_summary = None
            st.session_state.result_alerts  = []
            st.rerun()

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center; padding:36px 0 20px; color:#2a3d55; font-size:0.75rem;">
    🔒 Passive Read-Only Enclave · No packets transmitted back to source ·
    NTRO PS #26145
</div>
""", unsafe_allow_html=True)
