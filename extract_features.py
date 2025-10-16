import os
import pyshark
import pandas as pd
import numpy as np
import math
import tldextract  # pip install tldextract

import argparse

# --- Argument parsing ---
parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True, help="Path to input PCAP file")
parser.add_argument("--output", required=True, help="Path to output CSV")
args = parser.parse_args()

PCAP_PATH = args.input
OUT_AGG = args.output

# --- Helper functions ---
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def char_digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    letters = sum(c.isalpha() for c in s)
    digits = sum(c.isdigit() for c in s)
    return letters / digits if digits > 0 else float(letters)

def normalize_qname(qname: str) -> str:
    if not isinstance(qname, str):
        return ""
    return qname.lower().rstrip(".")

def extract_registered_domain(qname: str) -> str:
    if not qname:
        return ""
    ext = tldextract.extract(qname)
    return ext.registered_domain or qname

def is_nxdomain(resp_code: str, answers: int) -> int:
    try:
        rc = int(resp_code)
        if rc == 3:  # NXDOMAIN
            return 1
    except:
        pass
    return 1 if answers == 0 else 0

# --- Capture DNS packets ---
cap = pyshark.FileCapture(
    PCAP_PATH,
    display_filter="dns",
    tshark_path="/usr/bin/tshark"  # Linux default path
)


features = []

for pkt in cap:
    try:
        dns = pkt.dns

        qname = getattr(dns, "qry_name", "") or ""
        qname_norm = normalize_qname(qname)
        reg_domain = extract_registered_domain(qname_norm)
        qtype = getattr(dns, "qry_type", "")
        resp_code = getattr(dns, "resp_code", "")
        answers = int(getattr(dns, "count_answers", 0) or 0)
        queries = int(getattr(dns, "count_queries", 0) or 0)
        authorities = int(getattr(dns, "count_auth_rr", 0) or 0)
        additionals = int(getattr(dns, "count_add_rr", 0) or 0)
        length = int(getattr(pkt, "length", 0) or 0)

        features.append({
            "length": length,
            "query_name": qname_norm,
            "registered_domain": reg_domain,
            "query_type": qtype,
            "response_code": resp_code,
            "answers": answers,
            "queries": queries,
            "authorities": authorities,
            "additionals": additionals,
            "query_length": len(qname_norm),
            "entropy": shannon_entropy(qname_norm),
            "char_digit_ratio": char_digit_ratio(qname_norm),
            "is_nxdomain": is_nxdomain(resp_code, answers),
        })
    except AttributeError:
        continue  # Skip non-DNS packets

cap.close()

# --- Save raw per-query features ---
df = pd.DataFrame(features)
df.to_csv(OUT_RAW, index=False)
print(f"✅ Saved raw features to {OUT_RAW}, rows={len(df)}")
print(df.head())

# --- Aggregate per domain ---
agg = df.groupby("registered_domain").agg(
    total_queries=("query_name", "count"),
    nxdomain_count=("is_nxdomain", "sum"),
    nxdomain_ratio=("is_nxdomain", "mean"),
    avg_query_length=("query_length", "mean"),
    std_query_length=("query_length", "std"),
    avg_entropy=("entropy", "mean"),
    std_entropy=("entropy", "std"),
    avg_char_digit_ratio=("char_digit_ratio", "mean"),
    unique_subdomains=("query_name", lambda s: s.nunique()),
).fillna(0)

agg.to_csv(OUT_AGG, index=False)
print(f"✅ Saved aggregated features to {OUT_AGG}, domains={len(agg)}")

