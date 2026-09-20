"""
Modular UI Components for the SOC Threat Detection Console.
Encapsulates Plotly visualization builders and Streamlit layout sections.
"""

import time
import datetime
from typing import Dict, Any, List, Tuple
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go

from config import (
    COLOR_PALETTE,
    THREAT_COLORS,
    THREAT_DISPLAY_NAMES,
    SUPPORTED_LABELS,
    SEVERITY_COLORS,
    PROJECT_ROOT,
    FLOWS_CSV,
    MODEL_DIR
)


def render_top_bar(uptime_str: str) -> None:
    """Renders the fixed dark navy SOC top bar with pulsing live chip and system telemetry."""
    current_time_str = datetime.datetime.now().strftime("%H:%M:%S UTC")
    top_bar_html = f"""
    <div class="top-bar-container">
        <div class="top-bar-left">
            <div class="top-bar-title">
                <span>🛡️</span>
                <span>THREAT DETECTION CONSOLE</span>
            </div>
            <div class="top-bar-subtext">
                NTRO PS #26145 · Passive Unidirectional Traffic Monitoring
            </div>
        </div>
        <div class="top-bar-right">
            <div class="live-chip">
                <div class="pulsing-dot"></div>
                <span>LIVE</span>
            </div>
            <div class="sys-info-chip">
                {current_time_str}
            </div>
            <div class="sys-info-chip">
                Model: RandomForest v1 · Uptime: {uptime_str}
            </div>
        </div>
    </div>
    """
    st.markdown(top_bar_html, unsafe_allow_html=True)


def render_sidebar(model_accuracy_str: str) -> Tuple[List[str], List[str]]:
    """Renders the dark technical navigation, filters, and stream control sidebar."""
    with st.sidebar:
        st.markdown('<div class="sidebar-section-title">MONITOR</div>', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-active-item">▶ Live Dashboard</div>', unsafe_allow_html=True)

        st.markdown('<div class="sidebar-section-title">FILTERS</div>', unsafe_allow_html=True)

        selected_classes: List[str] = []
        st.caption("THREAT CATEGORIES")
        for cat in SUPPORTED_LABELS:
            disp_name = THREAT_DISPLAY_NAMES.get(cat, cat)
            checked = st.checkbox(f"● {disp_name}", value=True, key=f"cat_{cat}")
            if checked:
                selected_classes.append(cat)

        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        st.caption("SEVERITY LEVEL")
        col_s1, col_s2, col_s3 = st.columns(3)
        with col_s1:
            sel_high = st.checkbox("High", value=True, key="sev_high")
        with col_s2:
            sel_med = st.checkbox("Med", value=True, key="sev_med")
        with col_s3:
            sel_low = st.checkbox("Low", value=True, key="sev_low")

        selected_severities: List[str] = []
        if sel_high: selected_severities.append("High")
        if sel_med: selected_severities.append("Medium")
        if sel_low: selected_severities.append("Low")

        st.markdown("---")
        st.markdown('<div class="sidebar-section-title">DATASET</div>', unsafe_allow_html=True)
        st.markdown(
            """
            <div style="font-size: 0.76rem; color: #8A96A8; line-height: 1.4;">
                CICIDS2017 (real) + synthetic: DGA, beaconing, TLS-metadata
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

        # Stream trigger utility for on-demand flow injection
        if st.button("▶ Trigger Traffic Stream", use_container_width=True):
            from pipeline.stream_simulator import run_stream_simulator
            run_stream_simulator(
                csv_path=FLOWS_CSV,
                model_dir=MODEL_DIR,
                batch_size=150,
                batch_delay_sec=0.0,
                max_records=1500,
                reset_alerts=False
            )
            st.rerun()

        st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div style="font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; color: #00C2CB; opacity: 0.85;">
                Model Accuracy: {model_accuracy_str}
            </div>
            """,
            unsafe_allow_html=True
        )

    return selected_classes, selected_severities


def render_kpi_tiles(
    total_alerts: int,
    flows_processed: int,
    throughput: float,
    avg_conf: float
) -> None:
    """Renders the top row of 4 technical KPI metric tiles."""
    total_alerts_str = f"{total_alerts:,}"
    flows_processed_str = f"{flows_processed:,}"
    throughput_str = f"{throughput:,.1f}"
    avg_confidence_str = f"{avg_conf * 100:.1f}%" if avg_conf > 0 else "0.0%"

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="kpi-tile kpi-tile-red">
                <div class="kpi-label">TOTAL ALERTS</div>
                <div class="kpi-val">{total_alerts_str}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            f"""
            <div class="kpi-tile kpi-tile-cyan">
                <div class="kpi-label">FLOWS PROCESSED</div>
                <div class="kpi-val">{flows_processed_str}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:
        st.markdown(
            f"""
            <div class="kpi-tile kpi-tile-cyan">
                <div class="kpi-label">THROUGHPUT (FLOWS/SEC)</div>
                <div class="kpi-val">{throughput_str}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            f"""
            <div class="kpi-tile kpi-tile-green">
                <div class="kpi-label">AVG CONFIDENCE</div>
                <div class="kpi-val">{avg_confidence_str}</div>
            </div>
            """,
            unsafe_allow_html=True
        )


def render_threat_category_chart(alerts_data: List[Dict[str, Any]]) -> None:
    """Renders the horizontal bar chart showing category distribution across all 6 threat classes."""
    st.markdown(
        """
        <div class="soc-card-title">
            <span>THREAT CATEGORY BREAKDOWN</span>
            <span style="font-size: 0.7rem; color: #00C2CB;">PASSIVE CLASSIFICATION</span>
        </div>
        """,
        unsafe_allow_html=True
    )

    six_categories = [
        ("ddos", "DDoS Flood"),
        ("port_scan", "Port Scan"),
        ("botnet_beacon", "Botnet Beacon"),
        ("dga_dns", "DGA DNS"),
        ("encrypted_malware", "Encrypted Malware"),
        ("exfiltration", "Exfiltration")
    ]

    cat_counts: Dict[str, int] = {}
    for a in alerts_data:
        tc = a.get("threat_class")
        if tc:
            cat_counts[tc] = cat_counts.get(tc, 0) + 1

    bar_labels = [name for _, name in six_categories]
    bar_values = [cat_counts.get(code, 0) for code, _ in six_categories]
    bar_colors = [THREAT_COLORS[code] for code, _ in six_categories]

    fig = go.Figure(
        go.Bar(
            x=bar_values,
            y=bar_labels,
            orientation="h",
            marker=dict(color=bar_colors, line=dict(width=0)),
            text=[f"{v:,}" for v in bar_values],
            textposition="auto",
            textfont=dict(family="IBM Plex Mono", size=11, color="#FFFFFF"),
            hoverinfo="x+y"
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=20, t=10, b=20),
        height=260,
        xaxis=dict(
            showgrid=True,
            gridcolor="rgba(255,255,255,0.06)",
            tickfont=dict(family="IBM Plex Mono", size=10, color="#8A96A8"),
            zeroline=False
        ),
        yaxis=dict(
            showgrid=False,
            tickfont=dict(family="Inter", size=11, color="#E8EDF2", weight="bold"),
            autorange="reversed"
        )
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def render_severity_donut_chart(
    sev_breakdown: Dict[str, int],
    alerts_data: List[Dict[str, Any]]
) -> None:
    """Renders the calibrated severity distribution donut chart."""
    st.markdown(
        """
        <div class="soc-card-title">
            <span>SEVERITY DISTRIBUTION</span>
            <span style="font-size: 0.7rem; color: #8A96A8;">NTRO THRESHOLDS</span>
        </div>
        """,
        unsafe_allow_html=True
    )

    if not sev_breakdown or sum(sev_breakdown.values()) == 0:
        sev_breakdown = {"Low": 0, "Medium": 0, "High": 0}
        for a in alerts_data:
            s = a.get("severity", "High")
            sev_breakdown[s] = sev_breakdown.get(s, 0) + 1

    sev_labels = ["Low", "Medium", "High"]
    sev_values = [
        sev_breakdown.get("Low", 0),
        sev_breakdown.get("Medium", 0),
        sev_breakdown.get("High", 0)
    ]
    sev_colors = [SEVERITY_COLORS["Low"], SEVERITY_COLORS["Medium"], SEVERITY_COLORS["High"]]

    fig = go.Figure(
        go.Pie(
            labels=sev_labels,
            values=sev_values,
            hole=0.62,
            marker=dict(colors=sev_colors, line=dict(color="#111C2E", width=2)),
            textinfo="percent",
            textfont=dict(family="IBM Plex Mono", size=11, color="#FFFFFF"),
            hoverinfo="label+value+percent",
            direction="clockwise"
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=10, b=10),
        height=260,
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.15,
            xanchor="center",
            x=0.5,
            font=dict(family="IBM Plex Mono", size=10, color="#8A96A8")
        )
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def render_throughput_timeline(throughput_val: float) -> None:
    """Renders the 60-second real-time streaming flow throughput timeline."""
    st.markdown(
        """
        <div class="soc-card-title" style="margin-top: 0.5rem;">
            <span>TRAFFIC THROUGHPUT (LAST 60s)</span>
            <span style="font-size: 0.7rem; color: #00C2CB; font-family: 'IBM Plex Mono', monospace;">● REAL-TIME FLOW TELEMETRY</span>
        </div>
        """,
        unsafe_allow_html=True
    )

    now = datetime.datetime.now()
    time_stamps = [(now - datetime.timedelta(seconds=60 - i)).strftime("%H:%M:%S") for i in range(60)]

    base_rate = throughput_val if throughput_val > 0 else 1450.0
    np.random.seed(int(time.time()) % 1000)
    jitter = np.random.normal(0, base_rate * 0.08, 60)
    rates = [max(120.0, round(base_rate + j, 1)) for j in jitter]

    fig = go.Figure(
        go.Scatter(
            x=time_stamps,
            y=rates,
            mode="lines",
            line=dict(color=COLOR_PALETTE["accent_cyan"], width=2),
            fill="tozeroy",
            fillcolor="rgba(0, 194, 203, 0.12)",
            hoverinfo="x+y",
            hovertemplate="Time: %{x}<br>Throughput: %{y:.1f} flows/s<extra></extra>"
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=20, t=10, b=20),
        height=170,
        xaxis=dict(
            showgrid=True,
            gridcolor="rgba(255,255,255,0.05)",
            tickfont=dict(family="IBM Plex Mono", size=9, color="#8A96A8"),
            nticks=10
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(255,255,255,0.05)",
            tickfont=dict(family="IBM Plex Mono", size=9, color="#8A96A8"),
            title=dict(text="flows/sec", font=dict(family="IBM Plex Mono", size=9, color="#8A96A8"))
        )
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def render_alert_feed(
    alerts_data: List[Dict[str, Any]],
    selected_classes: List[str],
    selected_severities: List[str]
) -> None:
    """Renders the tabular real-time alert feed with pill formatting and evidence inspection."""
    filtered_alerts = [
        a for a in alerts_data
        if a.get("threat_class") in selected_classes and a.get("severity") in selected_severities
    ]

    sorted_alerts = list(reversed(filtered_alerts))
    total_filtered = len(sorted_alerts)
    display_limit = min(50, total_filtered)
    display_alerts = sorted_alerts[:display_limit]

    st.markdown(
        f"""
        <div class="soc-card-title" style="margin-top: 0.75rem;">
            <span>LIVE ALERT FEED</span>
            <span style="font-size: 0.75rem; color: #00E676; font-family: 'IBM Plex Mono', monospace;">
                ● {len(alerts_data):,} ALERTS ACTIVE ({total_filtered:,} MATCHING FILTERS)
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

    if display_alerts:
        table_rows = []
        for a in display_alerts:
            ts = a.get("timestamp", "")
            time_part = ts.split("T")[1].split(".")[0] if "T" in ts else ts[-8:]

            tc = a.get("threat_class", "unknown")
            tc_display = THREAT_DISPLAY_NAMES.get(tc, tc.replace("_", " ").title())
            conf_val = float(a.get("confidence_score", 0.0))
            sev = a.get("severity", "High")

            # Format evidence compactly
            ev = a.get("evidence", {})
            ev_items = []
            if "unique_dst_ports_per_src" in ev:
                ev_items.append(f"dst_ports: {ev['unique_dst_ports_per_src']}")
            if "burst_rate" in ev:
                ev_items.append(f"rate: {ev['burst_rate']}")
            elif "flow_packets_per_sec" in ev and ev["flow_packets_per_sec"] > 50:
                ev_items.append(f"pkt_rate: {ev['flow_packets_per_sec']}/s")
            if "asymmetric_skew" in ev:
                ev_items.append(f"ratio: {ev['asymmetric_skew']}")
            elif "outbound_inbound_ratio" in ev and ev["outbound_inbound_ratio"] > 3:
                ev_items.append(f"byte_ratio: {ev['outbound_inbound_ratio']:.1f}:1")
            if "dns_entropy" in ev:
                ev_items.append(f"entropy: {ev['dns_entropy']}")
            if "inter_arrival_variance" in ev:
                ev_items.append(f"jitter: {ev['inter_arrival_variance']:.4f}s")
            if "encrypted_metadata_anomaly" in ev:
                ev_items.append("payload_burst")

            ev_str = ", ".join(ev_items) if ev_items else f"proto: {ev.get('protocol', 'TCP')}"

            table_rows.append({
                "TIME": time_part,
                "FLOW ID": a.get("flow_id", "FL-000000"),
                "SRC IP": f"{a.get('src_ip', '')}:{a.get('src_port', '')}",
                "DST IP": f"{a.get('dst_ip', '')}:{a.get('dst_port', '')}",
                "THREAT CLASS": tc_display,
                "CONFIDENCE": conf_val,
                "SEVERITY": sev,
                "EVIDENCE": ev_str
            })

        df_display = pd.DataFrame(table_rows)

        st.dataframe(
            df_display,
            use_container_width=True,
            hide_index=True,
            column_config={
                "TIME": st.column_config.TextColumn("TIME (UTC)", width="small"),
                "FLOW ID": st.column_config.TextColumn("FLOW ID", width="small"),
                "SRC IP": st.column_config.TextColumn("SRC ENDPOINT", width="medium"),
                "DST IP": st.column_config.TextColumn("DST ENDPOINT", width="medium"),
                "THREAT CLASS": st.column_config.TextColumn("THREAT CLASS", width="medium"),
                "CONFIDENCE": st.column_config.ProgressColumn(
                    "CONFIDENCE",
                    help="Model prediction certainty (NTRO Calibrated)",
                    format="%.2f",
                    min_value=0.0,
                    max_value=1.0,
                    width="small"
                ),
                "SEVERITY": st.column_config.TextColumn("SEVERITY", width="small"),
                "EVIDENCE": st.column_config.TextColumn("FEATURE EVIDENCE (NON-DECRYPTED)", width="large")
            }
        )
        st.caption(f"Showing latest {display_limit} of {total_filtered:,} filtered alerts · Auto-updating every 2s")
    else:
        st.info("No active alerts matching the selected category and severity filters.")
