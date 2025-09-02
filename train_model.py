import pandas as pd
import re
import whois
import datetime
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Feature extraction
def extract_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc

    features["url_length"] = len(url)
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["count_hyphen"] = url.count('-')
    features["count_at"] = url.count('@')
    features["count_digits"] = sum(c.isdigit() for c in url)
    features["subdomain_count"] = domain.count('.')

    # WHOIS domain age
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.datetime.now() - creation).days if creation else 0
        features["domain_age"] = age
    except:
        features["domain_age"] = 0

    return features

# Load dataset
data = pd.read_csv("dataset.csv")  # columns: url,label (0=safe,1=phishing)
X = []
y = []

for i, row in data.iterrows():
    feats = extract_features(row["url"])
    X.append(list(feats.values()))
    y.append(row["label"])

X = pd.DataFrame(X, columns=extract_features("http://example.com").keys())

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
clf = RandomForestClassifier(n_estimators=200, random_state=42)
clf.fit(X_train, y_train)

# Save model
joblib.dump(clf, "model.pkl")

# Evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))
