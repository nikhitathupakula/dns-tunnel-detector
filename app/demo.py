# app/demo.py
import streamlit as st
import requests
import pandas as pd
import tempfile
import os
import subprocess

# 🧠 --- Page Config ---
st.set_page_config(page_title="DNS Tunneling Detection", page_icon="🧠")
st.title("🧠 DNS Tunneling Detection Demo")

# 🪄 --- Auto-detect backend URL ---
# Try to get API_URL from env variable first
API_URL = os.getenv("API_URL")

if not API_URL:
    # If not set, try to infer from Render deployment URL
    frontend_url = os.getenv("RENDER_EXTERNAL_URL")
    if frontend_url:
        # 👇 Adjust this replacement based on your Render service naming convention
        # Example: frontend: dns-frontend.onrender.com -> backend: dns-backend.onrender.com
        API_URL = frontend_url.replace("frontend", "backend")
    else:
        # Local fallback for development
        API_URL = "http://localhost:8000"

st.info(f"🔗 Using API URL: {API_URL}")

# 📂 --- File Upload ---
uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])

if uploaded_file is not None:
    # Save the uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_path = tmp_file.name

    st.info("Extracting features from PCAP... this may take a moment ⏳")

    out_path = os.path.join(tempfile.gettempdir(), "features.csv")

    # 🛠️ Run feature extractor with full error capture
    result = subprocess.run(
        ["python", "extract_features.py", "--input", tmp_path, "--output", out_path],
        capture_output=True,
        text=True
    )

    # 🧾 Show logs (for debugging)
    if result.stdout:
        st.text("stdout:\n" + result.stdout)
    if result.stderr:
        st.text("stderr:\n" + result.stderr)

    if result.returncode != 0 or not os.path.exists(out_path):
        st.error("❌ Feature extraction failed.")
        st.stop()
    else:
        df = pd.read_csv(out_path)
        st.write("Extracted features:", df.head())

    # 🧠 --- Detection ---
    if st.button("Run Detection"):
        st.info("Running predictions...")
        preds = []

        for _, row in df.iterrows():
            try:
                payload = {
                    "query_length": int(row["query_length"]),
                    "entropy": float(row["entropy"]),
                    "nxdomain_ratio": float(row["nxdomain_ratio"]),
                    "char_digit_ratio": float(row["char_digit_ratio"]),
                }
                response = requests.post(f"{API_URL}/predict", json=payload)
                response.raise_for_status()
                res = response.json()
                preds.append(res.get("prediction", "Unknown"))
            except Exception as e:
                preds.append("Error")
                st.error(f"Prediction error: {e}")

        df["prediction"] = preds
        st.success("✅ Detection complete!")
        st.dataframe(df[["registered_domain", "prediction"]])

        # ⚠️ Suspicious summary
        suspicious = df[df["prediction"] == "Suspicious"]
        st.warning(f"⚠️ Found {len(suspicious)} suspicious domains.")
