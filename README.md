
# 🛡️ Phishing Detection Tool (ML-based)

An **intermediate-level, production-ready** phishing detection CLI using **Random Forest** over URL-derived features.

## ✨ Features
- URL feature extraction (length, digits, hyphens, subdomains, IP in host, suspicious words, HTTPS, path/query length, domain age)
- WHOIS support for domain age (optional via `--no-whois` to avoid network dependency)
- JSON output option for integration
- Easy to train on your own dataset
- MIT License

## 📦 Project Structure
```
phishing-detector-ml/
├─ features.py
├─ train_model.py
├─ phishing_detector.py
├─ dataset.csv
├─ model.pkl
├─ requirements.txt
├─ LICENSE
└─ README.md
```

## 🚀 Quickstart
```bash
pip install -r requirements.txt
# (optional) retrain the model
python train_model.py

# Detect single or multiple URLs
python phishing_detector.py https://google.com http://paypal-login-security-update.com

# From a file
python phishing_detector.py urls.txt

# Fast mode (skip WHOIS)
python phishing_detector.py --no-whois https://example.com
```

## 🧪 Example
```
$ python phishing_detector.py https://google.com http://paypal-login-security-update.com --no-whois
https://google.com  ==>  SAFE  (p=0.994)
http://paypal-login-security-update.com  ==>  PHISHING  (p=0.978)
```

## 🧠 Training
Dataset format: CSV with columns: `url,label` where label is `0` for safe and `1` for phishing.
```
url,label
https://google.com,0
http://paypal-login-security-update.com,1
```
Train:
```bash
python train_model.py
```

## 🔒 Notes
- WHOIS lookups can be slow or fail on some networks; use `--no-whois` for reliability.
- This is for **educational and defensive** use only. Do not use it to attack or harm any systems.

## 📜 License
MIT
