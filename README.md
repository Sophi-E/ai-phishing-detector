# 🔒 AI-Powered Phishing Detector  

An intelligent phishing detection tool that combines **machine learning, threat intelligence APIs, and security best practices** to identify malicious URLs in real time.  

Built with:  
- 🧠 Scikit-Learn (ML classification on 30 URL/website features)  
- 🌍 IPinfo API (ASN & geolocation checks)  
- 🧪 VirusTotal API (reputation scoring)  
- 🎨 Streamlit (interactive web app UI)  
- 🐍 Python 3.10+  

---

## ✨ Features  

✅ **30 Security Features** — URL structure, SSL, domain age, WHOIS, etc.  
✅ **Threat Intelligence Integration** — VirusTotal & IPinfo checks for richer context.  
✅ **Machine Learning Model** — trained on a Kaggle phishing dataset.  
✅ **Real-Time Predictions** — paste a URL and get an instant verdict.  
✅ **Explainability** — outputs the full feature vector + risk notes.  
✅ **Streamlit Web UI** — clean, interactive interface for demos or deployment.  

---

## 📸 Demo  

![screenshot](docs/screenshot.png)    

---

## ⚡ Quickstart  

1. **Clone the repo**  
```bash
git clone https://github.com/YOUR-USERNAME/AI-Phishing-Detector.git
cd AI-Phishing-Detector
```
2. **Create virtual environment**
```bash
python -m venv .venv
source .venv/bin/activate   # Mac/Linux
.venv\Scripts\activate      # Windows
```
3. Install dependencies
```bash
pip install -r requirements.txt
```
4. Train the model (generates ```phishing_model.pkl```)
```bash
python phishing_detector.py
```
5. Run the app
```bash
streamlit run app.py
```

---
## 🔑 Environment Variables

Create a ```.env``` file in the project root:

IPINFO_API_KEY=your_ipinfo_token_here
VT_API_KEY=your_virustotal_token_here

---
## 🧑‍💻 Future Improvements

- [ ] Add SHAP/LIME explainability for feature importance  
- [ ] Deploy to Streamlit Cloud or Docker container  
- [ ] Expand training with live feeds (PhishTank, OpenPhish)  
- [ ] Add URL scanning history & dashboard  

