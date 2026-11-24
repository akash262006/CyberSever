"""
app.py - CyberSever: AI Network Anomaly Detection System
A professional cybersecurity Streamlit dashboard simulating an AI-driven NIDS with virtual hardware isolation.
"""

import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from traffic_generator import TrafficGenerator
from feature_extractor import FeatureExtractor
from anomaly_detector import AnomalyDetector
from virtual_hardware import VirtualHardwareController

# Page Configuration
st.set_page_config(
    page_title="CyberSever - AI Network Anomaly Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark Cybersecurity Theme Styling
st.markdown("""
<style>
    /* Main background and text */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    }
    
    /* Top title glow */
    .cyber-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: 1.5px;
        color: #38bdf8;
        text-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
        margin-bottom: 0px;
    }
    .cyber-subtitle {
        color: #94a3b8;
        font-size: 1.05rem;
        margin-bottom: 20px;
    }

    /* Cards */
    .metric-card {
        background: #131b2e;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 14px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .metric-title {
        color: #64748b;
        font-size: 0.8rem;
        text-transform: uppercase;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    .metric-value {
        font-size: 1.4rem;
        font-weight: 700;
        color: #f1f5f9;
        margin-top: 4px;
    }

    /* Status indicators */
    .status-badge-ok {
        background-color: rgba(34, 197, 94, 0.15);
        color: #4ade80;
        border: 1px solid rgba(34, 197, 94, 0.3);
        padding: 6px 12px;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
    }
    .status-badge-alert {
        background-color: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.3);
        padding: 6px 12px;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
        animation: pulse 1.5s infinite;
    }

    /* Hardware container */
    .hw-container {
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        margin-top: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Session State Initialization
if "hardware" not in st.session_state:
    st.session_state.hardware = VirtualHardwareController()

if "detector" not in st.session_state:
    detector = AnomalyDetector(contamination=0.05, random_state=42)
    detector.train_baseline(normal_samples=1000)
    st.session_state.detector = detector

if "extractor" not in st.session_state:
    st.session_state.extractor = FeatureExtractor(window_size=10)

if "generator" not in st.session_state:
    st.session_state.generator = TrafficGenerator()

if "traffic_history" not in st.session_state:
    st.session_state.traffic_history = []

if "is_simulating" not in st.session_state:
    st.session_state.is_simulating = False

hw: VirtualHardwareController = st.session_state.hardware
detector: AnomalyDetector = st.session_state.detector
extractor: FeatureExtractor = st.session_state.extractor
gen: TrafficGenerator = st.session_state.generator

# ----------------- 1. HEADER -----------------
st.markdown('<div class="cyber-title">🛡️ CyberSever</div>', unsafe_allow_html=True)
st.markdown('<div class="cyber-subtitle">AI Network Anomaly Detection System with Simulated Hardware Isolation | CNS Mini Project</div>', unsafe_allow_html=True)

# ----------------- 3. TRAFFIC SIMULATION (SIDEBAR) -----------------
st.sidebar.markdown("### 🕹️ Traffic Simulation")

scenario_choice = st.sidebar.selectbox(
    "Select Traffic Scenario",
    ["Normal Traffic", "DDoS-like Traffic", "Port Scanning", "Data Exfiltration"],
    index=0
)

# Simulation buttons
col_sim_btn1, col_sim_btn2 = st.sidebar.columns(2)
with col_sim_btn1:
    if st.sidebar.button("▶️ Start / Step", use_container_width=True, type="primary"):
        st.session_state.is_simulating = True

with col_sim_btn2:
    if st.sidebar.button("⏹️ Stop Simulation", use_container_width=True):
        st.session_state.is_simulating = False
        gen.stop()

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚡ Quarantine Controls")
if st.sidebar.button("🔄 Reset Quarantine", use_container_width=True):
    hw.reset_normal()
    extractor.reset_window()
    st.sidebar.success("Quarantine reset. Hardware returned to NORMAL.")

auto_quarantine = st.sidebar.toggle("Auto-Quarantine on ML Anomaly", value=True)

# Execute Simulation Step
if st.session_state.is_simulating:
    gen.start(scenario_choice)
    pkt = gen.generate_packet()
    feats = extractor.extract_features(pkt)
    is_anomaly, score, classification, explanation = detector.predict(feats)

    pkt_record = {
        **pkt,
        **feats,
        "anomaly_score": score,
        "ai_prediction": classification,
        "is_anomaly": is_anomaly,
        "explanation": explanation
    }
    st.session_state.traffic_history.append(pkt_record)
    if len(st.session_state.traffic_history) > 60:
        st.session_state.traffic_history.pop(0)

    # Hardware reaction
    if is_anomaly and auto_quarantine and hw.system_state == "NORMAL":
        hw.quarantine(reason=explanation, anomaly_score=score)

# ----------------- 2. SYSTEM STATUS -----------------
st.markdown("### 1. System Status")
hw_info = hw.get_status()

s1, s2, s3, s4 = st.columns(4)

with s1:
    net_status = "ACTIVE" if st.session_state.is_simulating else "STANDBY"
    badge_cls = "status-badge-ok" if st.session_state.is_simulating else "status-badge-ok"
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Network Monitoring</div>
        <div class="metric-value">{net_status}</div>
    </div>
    """, unsafe_allow_html=True)

with s2:
    ml_status = "ONLINE (Trained)" if detector.is_trained else "INITIALIZING"
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">ML Model Status</div>
        <div class="metric-value" style="color: #38bdf8;">Isolation Forest</div>
    </div>
    """, unsafe_allow_html=True)

with s3:
    iot_color = "#4ade80" if hw_info["iot_device"] == "ON" else "#f87171"
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Virtual IoT Device</div>
        <div class="metric-value" style="color: {iot_color};">{hw_info['iot_device']}</div>
    </div>
    """, unsafe_allow_html=True)

with s4:
    rel_color = "#4ade80" if hw_info["relay"] == "ON" else "#f87171"
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Virtual Relay</div>
        <div class="metric-value" style="color: {rel_color};">{hw_info['relay']} ({hw_info['relay_label']})</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ----------------- 4. LIVE MONITORING & 5. AI DETECTION -----------------
col_monitor, col_ai = st.columns([1, 1])

latest_pkt = st.session_state.traffic_history[-1] if st.session_state.traffic_history else None

with col_monitor:
    st.markdown("### 2. Live Network Monitoring")
    if latest_pkt:
        lm1, lm2 = st.columns(2)
        with lm1:
            st.metric("Packet Frequency", f"{latest_pkt['packet_rate']} pkts/s")
            st.metric("Connection Density", f"{latest_pkt['connection_density']}")
        with lm2:
            st.metric("Average Packet Size", f"{latest_pkt['avg_packet_size']} Bytes")
            st.metric("Outbound Bytes", f"{latest_pkt['outbound_data_volume']} Bytes")
    else:
        st.info("Awaiting traffic simulation... Click **'Start / Step'** in sidebar.")

with col_ai:
    st.markdown("### 3. AI Detection (Isolation Forest)")
    if latest_pkt:
        is_anom = latest_pkt["is_anomaly"]
        badge_text = "🚨 ANOMALOUS" if is_anom else "✅ NORMAL"
        badge_style = "status-badge-alert" if is_anom else "status-badge-ok"
        
        st.markdown(f"""
        <div style="margin-bottom: 15px;">
            <span class="{badge_style}" style="font-size: 1.1rem;">{badge_text}</span>
            <span style="margin-left: 15px; color: #94a3b8; font-weight: 500;">
                Anomaly Score: <b style="color: {'#f87171' if is_anom else '#4ade80'};">{latest_pkt['anomaly_score']}</b>
            </span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style="background: #1e293b; padding: 12px; border-radius: 8px; border-left: 4px solid {'#ef4444' if is_anom else '#22c55e'};">
            <span style="color: #94a3b8; font-size: 0.85rem; font-weight: 600;">DETECTION EXPLANATION:</span><br>
            <span style="color: #e2e8f0; font-size: 0.95rem;">{latest_pkt['explanation']}</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("Model ready for evaluation. Start simulation to observe ML inference.")

st.markdown("<br>", unsafe_allow_html=True)

# ----------------- 6. VIRTUAL HARDWARE -----------------
st.markdown("### 4. Virtual Hardware Controller")
st.caption("⚠️ Software simulation of ESP32, physical relay, LEDs and buzzer. (No real electrical disconnection).")

with st.container():
    h_col1, h_col2, h_col3, h_col4, h_col5 = st.columns(5)

    with h_col1:
        st.metric("ESP32 Controller", "ESP32-Node-01")
    with h_col2:
        st.metric("Relay State", f"{'🟢 ON' if hw_info['relay'] == 'ON' else '🔴 OFF (ISOLATED)'}")
    with h_col3:
        st.metric("Green LED", f"{'🟢 ON' if hw_info['green_led'] == 'ON' else '⚪ OFF'}")
    with h_col4:
        st.metric("Red LED", f"{'🔴 ON' if hw_info['red_led'] == 'ON' else '⚪ OFF'}")
    with h_col5:
        st.metric("Piezo Buzzer", f"{'🔊 ON (BEEPING)' if hw_info['buzzer'] == 'ON' else '🔇 OFF (SILENT)'}")

if hw_info["system_state"] == "QUARANTINE":
    st.error(f"🚨 **HARDWARE ISOLATION EVENT:** Device quarantined at `{hw_info['last_action_timestamp']}`.")
else:
    st.success(f"✅ **NORMAL OPERATION:** Hardware connected. Last action: `{hw_info['last_action_timestamp']}`.")

# Reset Button directly inside section as well
col_rst1, col_rst2 = st.columns([1, 4])
with col_rst1:
    if st.button("🔄 Reset Quarantine Button", type="secondary", use_container_width=True):
        hw.reset_normal()
        extractor.reset_window()
        st.rerun()

with col_rst2:
    if hw_info["last_http_post"]:
        with st.expander("📡 View Simulated ESP32 JSON HTTP POST Command"):
            st.json(hw_info["last_http_post"])

st.markdown("<br>", unsafe_allow_html=True)

# ----------------- 7. GRAPHS -----------------
st.markdown("### 5. Network Traffic & Anomaly Graphs")

if st.session_state.traffic_history:
    df_hist = pd.DataFrame(st.session_state.traffic_history)
    
    tab_g1, tab_g2 = st.columns(2)
    
    with tab_g1:
        # Network traffic over time
        fig_time = px.line(
            df_hist.reset_index(),
            x=df_hist.reset_index().index,
            y="packet_rate",
            color="ai_prediction",
            color_discrete_map={"NORMAL": "#22c55e", "ANOMALOUS": "#ef4444"},
            markers=True,
            title="Network Traffic Rate Over Time (pkts/sec)",
            labels={"x": "Sample Index", "packet_rate": "Packet Rate (pkts/s)"},
            template="plotly_dark"
        )
        fig_time.update_layout(paper_bgcolor="#0f172a", plot_bgcolor="#0f172a")
        st.plotly_chart(fig_time, use_container_width=True)

    with tab_g2:
        # Normal vs Anomalous scatter
        fig_scatter = px.scatter(
            df_hist,
            x="packet_size",
            y="outbound_data_volume",
            color="ai_prediction",
            color_discrete_map={"NORMAL": "#22c55e", "ANOMALOUS": "#ef4444"},
            size="packet_rate",
            title="Normal vs Anomalous Traffic (Packet Size vs Outbound Volume)",
            labels={"packet_size": "Packet Size (Bytes)", "outbound_data_volume": "Outbound Volume (Bytes)"},
            template="plotly_dark"
        )
        fig_scatter.update_layout(paper_bgcolor="#0f172a", plot_bgcolor="#0f172a")
        st.plotly_chart(fig_scatter, use_container_width=True)

    # Anomaly detection history score plot
    fig_score = go.Figure()
    fig_score.add_trace(go.Scatter(
        y=df_hist["anomaly_score"],
        mode="lines+markers",
        name="Isolation Forest Score",
        line=dict(color="#38bdf8", width=2),
        marker=dict(
            size=7,
            color=["#ef4444" if a else "#22c55e" for a in df_hist["is_anomaly"]]
        )
    ))
    fig_score.add_hline(y=0.0, line_dash="dash", line_color="#f59e0b", annotation_text="Anomaly Threshold (0.0)")
    fig_score.update_layout(
        title="Anomaly Detection History (Isolation Forest Scores < 0.0 Flagged as Threat)",
        yaxis_title="Anomaly Score",
        xaxis_title="Packet Stream Index",
        template="plotly_dark",
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        height=320
    )
    st.plotly_chart(fig_score, use_container_width=True)

    # Inspection Table
    with st.expander("📜 View Raw Traffic Data Log"):
        st.dataframe(df_hist.tail(20)[[
            "source_ip", "destination_port", "packet_rate", "avg_packet_size",
            "connection_density", "outbound_data_volume", "scenario", "ai_prediction", "anomaly_score", "explanation"
        ]].iloc[::-1], use_container_width=True)
else:
    st.info("Simulation history is currently empty. Start simulation from the sidebar.")
