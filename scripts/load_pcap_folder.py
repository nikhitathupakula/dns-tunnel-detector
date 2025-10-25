# scripts/extract_dns_features_per_packet.py

import os
import math
import argparse
import pandas as pd
from scapy.all import DNS, DNSQR, DNSRR, PcapReader

def shannon_entropy(text):
    if not text:
        return 0.0
    probs = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)

def safe_decode(field):
    try:
        if isinstance(field, bytes):
            return field.decode(errors="ignore")
        return str(field)
    except:
        return ""

def extract_features_from_packet(pkt):
    if not pkt.haslayer(DNS):
        return None
    
    dns = pkt[DNS]
    qd = dns.qd if dns.qr == 0 else None  # Query only if it's a query packet
    an = dns.an if dns.qr == 1 else None  # Response fields only if response
    ar = dns.ar if dns.qr == 1 else None

    # ---------------- Query-based fields ----------------
    qname = safe_decode(getattr(qd, "qname", "")) if qd else ""
    qd_qname_len = len(qname)
    qd_qname_shannon = shannon_entropy(qname)
    qd_qtype = getattr(qd, "qtype", 0) if qd else 0

    # ---------------- DNS Header Counts ----------------
    qdcount = getattr(dns, "qdcount", 0)
    ancount = getattr(dns, "ancount", 0)
    arcount = getattr(dns, "arcount", 0)
    nscount = getattr(dns, "nscount", 0)

    # ---------------- Answer Section Features ----------------
    if an:
        an_name = safe_decode(getattr(an, "rrname", ""))
        an_rrname_len = len(an_name)
        an_rrname_shannon = shannon_entropy(an_name)
        an_type = getattr(an, "type", 0)
        an_ttl = getattr(an, "ttl", 0)
        an_rdata = safe_decode(getattr(an, "rdata", ""))
        an_rdata_len = len(an_rdata)
        an_rdata_shannon = shannon_entropy(an_rdata)
    else:
        an_rrname_len = 0
        an_rrname_shannon = 0.0
        an_type = 0
        an_ttl = 0
        an_rdata_len = 0
        an_rdata_shannon = 0.0

    # ---------------- Additional Records ----------------
    if ar:
        ar_name = safe_decode(getattr(ar, "rrname", ""))
        ar_rrname_len = len(ar_name)
        ar_rrname_shanonn = shannon_entropy(ar_name)  # ✅ kept misspelling
        ar_type = getattr(ar, "type", 0)
        ar_rdata = safe_decode(getattr(ar, "rdata", ""))
        ar_rdata_len = len(ar_rdata)
        ar_rdata_shannon = shannon_entropy(ar_rdata)
    else:
        ar_rrname_len = 0
        ar_rrname_shanonn = 0.0
        ar_type = 0
        ar_rdata_len = 0
        ar_rdata_shannon = 0.0

    return {
        "qd_qname_len": qd_qname_len,
        "qd_qname_shannon": qd_qname_shannon,
        "qdcount": qdcount,
        "ancount": ancount,
        "arcount": arcount,
        "nscount": nscount,
        "qd_qtype": qd_qtype,
        "an_rrname_len": an_rrname_len,
        "an_rrname_shannon": an_rrname_shannon,
        "an_type": an_type,
        "an_ttl": an_ttl,
        "an_rdata_len": an_rdata_len,
        "an_rdata_shannon": an_rdata_shannon,
        "ar_rrname_len": ar_rrname_len,
        "ar_rrname_shanonn": ar_rrname_shanonn,
        "ar_type": ar_type,
        "ar_rdata_len": ar_rdata_len,
        "ar_rdata_shannon": ar_rdata_shannon,
    }

def process_folder(folder_path, label):
    all_rows = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            if f.lower().endswith(".pcap"):
                pcap_path = os.path.join(root, f)
                print(f"➡️ Extracting from {f}")
                try:
                    with PcapReader(pcap_path) as packets:
                        for pkt in packets:
                            row = extract_features_from_packet(pkt)
                            if row:
                                row["file"] = f
                                row["label"] = label
                                all_rows.append(row)
                except Exception as e:
                    print(f"⚠️ Error processing {f}: {e}")
    return all_rows

def main(input_dir, output_csv):
    results = []

    benign = os.path.join(input_dir, "benign")
    malicious = os.path.join(input_dir, "malicious")

    if os.path.isdir(benign):
        results.extend(process_folder(benign, 0))
    if os.path.isdir(malicious):
        results.extend(process_folder(malicious, 1))

    if results:
        df = pd.DataFrame(results)
        df.to_csv(output_csv, index=False)
        print(f"\n✅ Saved {len(df)} rows to → {output_csv}")
    else:
        print("❌ No DNS packets extracted")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract DNS packet features from PCAP")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    main(args.input, args.output)
