"""
Cyber Threat Detection Console — Real-Time SOC Monitoring Screen
NTRO Problem Statement #26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Orchestrates the SOC dashboard by integrating modular styling, data caching,
and real-time visualization components.
"""

import sys
import time
from pathlib import Path
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# Configure project path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.styles import get_soc_styles
from dashboard.data_loader import load_live_data, get_model_accuracy
from dashboard.components import (
    render_top_bar,
    render_sidebar,
    render_kpi_tiles,
    render_threat_category_chart,
    render_severity_donut_chart,
    render_throughput_timeline,
    render_alert_feed,
)

# 1. Page Configuration
st.set_page_config(
    page_title="THREAT DETECTION CONSOLE | NTRO PS #26145",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Inject Styles & Auto-Refresh
st.markdown(get_soc_styles(), unsafe_allow_html=True)
st_autorefresh(interval=2000, key="soc_live_refresh")

if "session_start_time" not in st.session_state:
    st.session_state.session_start_time = time.time()

# 3. Load Real-Time Pipeline Telemetry
summary_data, alerts_data = load_live_data()
model_accuracy_str = get_model_accuracy()

# 4. Render Top Bar & Sidebar Navigation
uptime_sec = int(time.time() - st.session_state.session_start_time)
hours, rem = divmod(uptime_sec, 3600)
minutes, seconds = divmod(rem, 60)
uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

render_top_bar(uptime_str)
selected_classes, selected_severities = render_sidebar(model_accuracy_str)

# 5. Row 1: KPI Stat Tiles
total_alerts = summary_data.get("total_alerts", len(alerts_data))
flows_processed = summary_data.get("total_flows_processed", int(total_alerts * 2.05))
throughput = summary_data.get("measured_throughput_flows_per_sec", 0.0)
avg_conf = summary_data.get("avg_confidence_score", 0.0)

render_kpi_tiles(total_alerts, flows_processed, throughput, avg_conf)

# 6. Row 2: Charts Side by Side (65% / 35%)
col_left, col_right = st.columns([0.65, 0.35])
with col_left:
    render_threat_category_chart(alerts_data)
with col_right:
    render_severity_donut_chart(summary_data.get("severity_breakdown", {}), alerts_data)

# 7. Row 3: Throughput Timeline
render_throughput_timeline(throughput)

# 8. Row 4: Live Alert Feed
render_alert_feed(alerts_data, selected_classes, selected_severities)
