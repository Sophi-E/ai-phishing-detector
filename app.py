import streamlit as st
import joblib
import pandas as pd
from feature_extraction import extract_features

st.set_page_config(page_title="AI Phishing Detector", page_icon="🔒")

@st.cache_resource
def load_model():
    return joblib.load("phishing_model.pkl")

model = load_model()

st.title("🔒 AI-Powered Phishing Detector")
st.write("Paste a URL and get a prediction based on 30 security features.")

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

        if pred == 1:
            st.error("🚨 Phishing")
        else:
            st.success("✅ Safe")

        st.caption(f"Feature vector (30): {feats}")
        if proba is not None:
            st.caption(f"Probabilities [Safe, Phishing]: {proba}")
