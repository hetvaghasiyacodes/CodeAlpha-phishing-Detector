import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Dummy dataset (replace with your dataset if available)
data = {
    "has_https": [1, 0, 1, 0, 1, 0, 1, 0, 1, 0],
    "url_length": [23, 120, 35, 200, 15, 180, 45, 160, 30, 175],
    "has_at_symbol": [0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
    "label": [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]  # 0 = safe, 1 = phishing
}

df = pd.DataFrame(data)

X = df.drop("label", axis=1)
y = df["label"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred) * 100, "%")
print(classification_report(y_test, y_pred))

# Save model directly (not dict)
joblib.dump(model, "model.pkl")
print("✅ Model saved to model.pkl")
