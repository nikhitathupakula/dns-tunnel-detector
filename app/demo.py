# app/demo.py
import streamlit as st
import requests

st.title("DNS Tunneling Detection Demo")

query_length = st.slider("Query Length", 1, 200, 50)
entropy = st.slider("Entropy", 0.0, 8.0, 3.5)
nxdomain_ratio = st.slider("NXDOMAIN Ratio", 0.0, 1.0, 0.2)
char_digit_ratio = st.slider("Char/Digit Ratio", 0.0, 2.0, 0.5)

if st.button("Check"):
    payload = {
        "query_length": query_length,
        "entropy": entropy,
        "nxdomain_ratio": nxdomain_ratio,
        "char_digit_ratio": char_digit_ratio
    }
    res = requests.post("http://127.0.0.1:8000/predict", json=payload).json()
    st.write("Prediction:", res["prediction"])
#not added only
