"""
Dashboard CSS Styles and Visual Design Tokens.
Provides responsive, high-density dark SOC styling.
"""

def get_soc_styles() -> str:
    """Returns the CSS string for the SOC dashboard theme."""
    return """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        background-color: #0A0E17 !important;
        color: #E8EDF2;
    }

    .stApp {
        background-color: #0A0E17;
    }

    /* Fixed Top Bar */
    .top-bar-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background-color: #0B1E33;
        padding: 12px 24px;
        border-bottom: 2px solid #00C2CB;
        margin-top: -50px;
        margin-left: -3rem;
        margin-right: -3rem;
        margin-bottom: 1.25rem;
    }

    .top-bar-left {
        display: flex;
        flex-direction: column;
    }

    .top-bar-title {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 1.15rem;
        font-weight: 700;
        letter-spacing: 2px;
        color: #FFFFFF;
        text-transform: uppercase;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .top-bar-subtext {
        font-size: 0.75rem;
        color: #8A96A8;
        letter-spacing: 0.5px;
        margin-top: 2px;
    }

    .top-bar-right {
        display: flex;
        align-items: center;
        gap: 16px;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.8rem;
    }

    /* Pulsing Live Chip */
    .live-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(0, 230, 118, 0.12);
        border: 1px solid rgba(0, 230, 118, 0.4);
        border-radius: 4px;
        padding: 3px 10px;
        color: #00E676;
        font-weight: 600;
        font-size: 0.75rem;
        letter-spacing: 1px;
    }

    .pulsing-dot {
        width: 8px;
        height: 8px;
        background-color: #00E676;
        border-radius: 50%;
        box-shadow: 0 0 8px #00E676;
        animation: pulse-animation 1.6s infinite ease-in-out;
    }

    @keyframes pulse-animation {
        0% { transform: scale(0.9); opacity: 0.7; box-shadow: 0 0 2px #00E676; }
        50% { transform: scale(1.2); opacity: 1; box-shadow: 0 0 10px #00E676; }
        100% { transform: scale(0.9); opacity: 0.7; box-shadow: 0 0 2px #00E676; }
    }

    .sys-info-chip {
        background: #111C2E;
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 3px 10px;
        border-radius: 4px;
        color: #8A96A8;
        font-size: 0.75rem;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0A1826 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.08);
        padding-top: 1rem;
    }

    section[data-testid="stSidebar"] hr {
        border-color: rgba(255, 255, 255, 0.08);
        margin: 1rem 0;
    }

    .sidebar-section-title {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.7rem;
        font-weight: 700;
        color: #8A96A8;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }

    .sidebar-active-item {
        background: rgba(0, 194, 203, 0.08);
        border-left: 3px solid #00C2CB;
        color: #00C2CB;
        padding: 8px 12px;
        font-weight: 600;
        font-size: 0.85rem;
        border-radius: 0 4px 4px 0;
        margin-bottom: 0.5rem;
    }

    /* KPI Stat Tiles */
    .kpi-tile {
        background-color: #111C2E;
        border-radius: 4px;
        padding: 14px 18px;
        border: 1px solid rgba(255, 255, 255, 0.06);
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        margin-bottom: 1rem;
    }

    .kpi-tile-red { border-left: 4px solid #FF4B4B !important; }
    .kpi-tile-cyan { border-left: 4px solid #00C2CB !important; }
    .kpi-tile-green { border-left: 4px solid #00E676 !important; }

    .kpi-val {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 2rem;
        font-weight: 700;
        color: #FFFFFF;
        line-height: 1.1;
        margin-top: 4px;
        margin-bottom: 4px;
    }

    .kpi-label {
        font-family: 'Inter', sans-serif;
        font-size: 0.72rem;
        font-weight: 600;
        color: #8A96A8;
        letter-spacing: 1.2px;
        text-transform: uppercase;
    }

    /* Section Card Containers */
    .soc-card-title {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.78rem;
        font-weight: 700;
        color: #8A96A8;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        margin-bottom: 12px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    /* Hide default Streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 100% !important;
    }
    </style>
    """
