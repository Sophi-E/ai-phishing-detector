import streamlit as st
import joblib
import pandas as pd
import json
import os

from feature_extraction import extract_features, get_ipinfo_data, get_virustotal_data

st.set_page_config(page_title="AI Phishing Detector", page_icon="🔒")

# --- Load model ---
@st.cache_resource
def load_model():
    return joblib.load("phishing_model.pkl")

model = load_model()

# --- Load bad ASN list ---
BAD_ASNS_PATH = os.path.join(os.path.dirname(__file__), "bad_asns.json")
if os.path.exists(BAD_ASNS_PATH):
    with open(BAD_ASNS_PATH) as f:
        BAD_ASNS = json.load(f)
else:
    BAD_ASNS = {}

# --- IPinfo risk check ---
def check_ipinfo_risk(ipinfo_data):
    score = 0
    notes = []
    if not ipinfo_data or "error" in ipinfo_data:
        return score, ["No IPinfo data"]

    asn = ipinfo_data.get("asn", {}).get("asn", "")
    org = ipinfo_data.get("org", "")
    country = ipinfo_data.get("country", "")

    if asn in BAD_ASNS:
        score += 10
        notes.append(f"ASN {asn} flagged: {BAD_ASNS[asn]}")

    if "VPS" in org.upper() or "CLOUD" in org.upper():
        score += 5
        notes.append(f"Suspicious org: {org}")

    risky_countries = ["SC", "PA", "VG", "RU", "CN"]
    if country in risky_countries:
        score += 5
        notes.append(f"High-risk country: {country}")

    return score, notes

# --- Unified Threat Score ---
def compute_threat_score(pred, probs, vt_stats, ipinfo_data):
    score = 0
    notes = []

    # ML model (50%)
    if pred == 1:
        score += int(50 * (probs[1] if probs is not None else 1))
        notes.append("ML model predicted phishing")
    else:
        score += int(10 * (probs[1] if probs is not None else 0))
        notes.append("ML model predicted safe")

    # VirusTotal (40%)
    if vt_stats and "error" not in vt_stats:
        malicious = vt_stats.get("malicious", 0)
        suspicious = vt_stats.get("suspicious", 0)
        if malicious > 5:
            score += 40
            notes.append(f"VirusTotal: {malicious} vendors flagged malicious")
        elif malicious > 0:
            score += 30
            notes.append(f"VirusTotal: {malicious} vendors flagged malicious")
        elif suspicious > 2:
            score += 20
            notes.append(f"VirusTotal: {suspicious} vendors flagged suspicious")
        elif suspicious > 0:
            score += 10
            notes.append(f"VirusTotal: {suspicious} vendors flagged suspicious")
        else:
            notes.append("VirusTotal: No issues found")

    # IPinfo (10%)
    ip_score, ip_notes = check_ipinfo_risk(ipinfo_data)
    score += ip_score
    for note in ip_notes:
        # If ASN is flagged, make it stand out in red
        if "ASN" in note:
            notes.append(f"🌍 **{note}**")
        else:
            notes.append(f"🌍 {note}")

    # Cap at 100
    score = min(score, 100)

    # Risk label
    if score <= 30:
        label, color = "✅ Low Risk (Safe)", "green"
    elif score <= 70:
        label, color = "⚠️ Medium Risk (Suspicious)", "orange"
    else:
        label, color = "🚨 High Risk (Phishing Likely)", "red"

    return score, label, color, notes

# --- UI ---
st.title("🔒 AI-Powered Phishing Detector")
st.write("Paste a URL and get a prediction based on 30+ security features, VirusTotal, and IPinfo reputation checks.")

url = st.text_input("URL", placeholder="https://example.com/login")

if st.button("Check URL"):
    if not url.strip():
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Analyzing…"):
            feats = extract_features(url)
            X = pd.DataFrame([feats])
            pred = model.predict(X)[0]
            proba = None
            try:
                proba = model.predict_proba(X)[0]
            except Exception:
                pass

            vt_stats = get_virustotal_data(url)
            ipinfo_data = get_ipinfo_data(url)

            score, risk_label, color, notes = compute_threat_score(pred, proba, vt_stats, ipinfo_data)

        # Final result
        st.subheader("🛡 Unified Threat Score")
        st.markdown(
            f"<div style='padding:12px;background-color:{color};color:white;border-radius:8px;font-size:18px'>{risk_label} — Score: {score}/100</div>", 
            unsafe_allow_html=True
        )

        st.subheader("📊 Analysis Details")
        st.write("**ML Features (30):**", feats)
        if proba is not None:
            st.write("**ML Probabilities [Safe, Phishing]:**", proba)
        st.write("**VirusTotal Stats:**", vt_stats)
        st.write("**IPinfo Data:**", ipinfo_data)

        st.subheader("📝 Risk Notes")
        for note in notes:
            st.markdown(f"- {note}")
