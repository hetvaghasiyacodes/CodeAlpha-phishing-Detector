
import argparse, json
import joblib
from features import extract_features, feature_order_example

def predict_url(url, model_bundle, use_whois=True):
    cols = model_bundle["columns"]
    feats = extract_features(url, use_whois=use_whois)
    X = [[feats.get(c, 0) for c in cols]]
    y = model_bundle["model"].predict(X)[0]
    proba = None
    if hasattr(model_bundle["model"], "predict_proba"):
        proba = float(model_bundle["model"].predict_proba(X)[0][int(y)])
    return {
        "url": url,
        "label": "PHISHING" if int(y)==1 else "SAFE",
        "probability": proba,
        "features": feats
    }

def main():
    ap = argparse.ArgumentParser(description="ML-based Phishing Detection Tool")
    ap.add_argument("inputs", nargs="+", help="URL(s) or a path to a text file with one URL per line")
    ap.add_argument("--no-whois", action="store_true", help="Disable WHOIS (faster & avoids network issues)")
    ap.add_argument("--json", action="store_true", help="Print JSON output")
    args = ap.parse_args()

    # Load model
    bundle = joblib.load("model.pkl")

    # Gather URLs
    urls = []
    for inp in args.inputs:
        try:
            # If it's a file, read URLs
            with open(inp, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        urls.append(line)
        except Exception:
            urls.append(inp)  # treat as URL

    results = [predict_url(u, bundle, use_whois=not args.no_whois) for u in urls]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['url']}  ==>  {r['label']}  ({'p=' + str(round(r['probability'],3)) if r['probability'] is not None else 'prob? '-' '})")

if __name__ == "__main__":
    main()
