# app/demo.py
import streamlit as st
import requests
import pandas as pd
import tempfile
import os
import subprocess

st.set_page_config(page_title="DNS Tunneling Detection", page_icon="🧠")
st.title("🧠 DNS Tunneling Detection Demo")

uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])

if uploaded_file is not None:
    # Save the uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_path = tmp_file.name

    st.info("Extracting features from PCAP... this may take a moment ⏳")

    # Run your existing feature extractor (extract_features.py)
    # Assuming it takes input and output arguments
    out_path = os.path.join(tempfile.gettempdir(), "features.csv")
    os.system(f"python extract_features.py --input {tmp_path} --output {out_path}")
    
    if not os.path.exists(out_path):
        st.error("❌ Feature extraction failed.")
    else:
        df = pd.read_csv(out_path)
        
    st.write("Extracted features:", df.head())

    if st.button("Run Detection"):
        st.info("Running predictions...")
        preds = []
        for _, row in df.iterrows():
            payload = row.to_dict()
            API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
            res = requests.post(f"{API_URL}/predict", json=payload).json()
            preds.append(res["prediction"])

        df["prediction"] = preds
        st.success("✅ Detection complete!")
        st.dataframe(df[["registered_domain", "prediction"]])

        suspicious = df[df["prediction"] == "Suspicious"]
        st.warning(f"⚠️ Found {len(suspicious)} suspicious domains.")
