import joblib
import re
import argparse
import pyfiglet
import os
import time
import sys
from termcolor import colored
from colorama import Fore, Style, init
from tqdm import tqdm

# Colorama init
init(autoreset=True)

# Load trained ML model
model = joblib.load("model.pkl")

# -------- Banner Section --------
def rainbow_text(text):
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.MAGENTA]
    result = ""
    for i, char in enumerate(text):
        result += colors[i % len(colors)] + char
    return result

def show_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = pyfiglet.figlet_format("Phishing Detector", font="slant")
    print(rainbow_text(banner))
    print(Fore.YELLOW + "🔒 Developed by Het Vaghasiya (@hackwithhet)\n")

# -------- Feature Extraction --------
def extract_features(url):
    return [
        len(url), 
        url.count('.'),
        1 if "https" in url else 0,
        1 if "@" in url else 0,
        1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url) else 0
    ]

# -------- Progress Bar Animation --------
def show_progress(task="Analyzing URL"):
    for _ in tqdm(range(30), desc=task, ncols=100, colour="green"):
        time.sleep(0.05)

# -------- Detection --------
def predict_url(url):
    show_progress("🔍 Scanning")
    features = extract_features(url)
    prediction = model.predict([features])[0]
    
    if prediction == 1:
        print(Fore.RED + Style.BRIGHT + f"\n🚨 PHISHING DETECTED: {url}\n")
    else:
        print(Fore.GREEN + Style.BRIGHT + f"\n✅ SAFE WEBSITE: {url}\n")

# -------- Main --------
def main():
    parser = argparse.ArgumentParser(description="Phishing Detector Tool")
    parser.add_argument("urls", nargs="+", help="Enter one or more URLs to check")
    args = parser.parse_args()

    show_banner()

    for url in args.urls:
        predict_url(url)

if __name__ == "__main__":
    main()
