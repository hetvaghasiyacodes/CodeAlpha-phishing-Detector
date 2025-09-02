
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from features import extract_features, feature_order_example

def vectorize(urls, use_whois=False):
    cols = feature_order_example()
    rows = []
    for u in urls:
        feats = extract_features(u, use_whois=use_whois)
        rows.append([feats[c] for c in cols])
    return pd.DataFrame(rows, columns=cols)

def main():
    # Expect dataset.csv with columns: url,label (0=safe,1=phishing)
    df = pd.read_csv("dataset.csv")
    X = vectorize(df["url"].tolist(), use_whois=False)  # speedy, stable
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    clf = RandomForestClassifier(
        n_estimators=300, max_depth=None, random_state=42, n_jobs=-1
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("Accuracy:", round(accuracy_score(y_test, y_pred)*100, 2), "%")
    print(classification_report(y_test, y_pred, digits=4))

    joblib.dump({"model": clf, "columns": list(X.columns)}, "model.pkl")
    print("Saved model to model.pkl")

if __name__ == "__main__":
    main()
