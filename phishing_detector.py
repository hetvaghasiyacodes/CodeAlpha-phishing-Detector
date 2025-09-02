import joblib
from urllib.parse import urlparse
import whois
import datetime

# Load trained model
model = joblib.load("model.pkl")

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    features = {}
    features["url_length"] = len(url)
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["count_hyphen"] = url.count('-')
    features["count_at"] = url.count('@')
    features["count_digits"] = sum(c.isdigit() for c in url)
    features["subdomain_count"] = domain.count('.')
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.datetime.now() - creation).days if creation else 0
        features["domain_age"] = age
    except:
        features["domain_age"] = 0
    return list(features.values())

def predict_url(url):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    return "PHISHING" if prediction == 1 else "SAFE"

if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "http://paypal-login-security-update.com",
        "https://github.com",
        "http://secure-login-facebook-update.net"
    ]
    for u in test_urls:
        print(u, "==>", predict_url(u))
