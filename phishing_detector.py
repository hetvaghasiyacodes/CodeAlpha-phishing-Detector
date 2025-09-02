import joblib
import argparse
import pyfiglet
from termcolor import colored
from tqdm import tqdm
import time
import random

# Load trained model
model = joblib.load("model.pkl")

# Fancy Banner
banner = pyfiglet.figlet_format("Phishing Detector")
print(colored(banner, "cyan", attrs=["bold"]))
print(colored("🔒 Developed by Het Vaghasiya (@hackwithhet)\n", "yellow", attrs=["bold"]))

def extract_features(url):
    features = {}
    features["has_https"] = 1 if url.startswith("https") else 0
    features["url_length"] = len(url)
    features["has_at_symbol"] = 1 if "@" in url else 0
    return [features["has_https"], features["url_length"], features["has_at_symbol"]]

def fancy_loader(task="Analyzing URL"):
    print(colored(f"\n🚀 {task}...\n", "magenta", attrs=["bold"]))
    for _ in tqdm(range(40), desc="Progress", ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.05)

def predict_url(url):
    print(colored(f"\n🌐 Target URL: {url}", "blue", attrs=["bold"]))
    fancy_loader("Extracting Features")

    features = extract_features(url)
    prediction = model.predict([features])[0]

    # Random delay for realistic effect
    time.sleep(random.uniform(0.5, 1.5))

    if prediction == 1:
        print(colored("\n⚠️ ALERT: This website looks like a PHISHING site!", "red", attrs=["bold", "blink"]))
        print(colored("💀 Action Recommended: Do NOT enter your credentials here.\n", "red"))
    else:
        print(colored("\n✅ SAFE: This website seems legitimate.", "green", attrs=["bold"]))
        print(colored("🛡️ You can browse safely!\n", "green"))

def main():
    parser = argparse.ArgumentParser(description="Phishing Detection Tool")
    parser.add_argument("urls", nargs="+", help="List of URLs to scan")
    args = parser.parse_args()

    for url in args.urls:
        predict_url(url)

if __name__ == "__main__":
    main()
