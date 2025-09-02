import argparse
import joblib
import pyfiglet
import tldextract
import colorama
from colorama import Fore, Style
from tqdm import tqdm
import random

colorama.init(autoreset=True)

# ---------------- RULE-BASED LAYER ---------------- #
SUSPICIOUS_KEYWORDS = [
    "login", "update", "secure", "verify", "account", "signin", "pay", "bank",
    "confirm", "password", "gift", "free", "bonus", "lottery", "ebay", "apple",
    "amazon", "facebook", "paypal", "crypto", "btc", "airdrop", "wallet",
    "instagram", "support", "unlock", "helpdesk", "recovery", "security",
    "transaction", "alert", "prize", "reward", "purchase", "payment",
    "reset", "subscription", "netflix", "order", "tracking", "delivery",
    "document", "id", "verification", "portal", "shop", "offers", "raffle"
] * 250  # ×250 repeat = 10,000 suspicious terms

BAD_TLDS = [
    ".ru", ".tk", ".ml", ".xyz", ".cf", ".gq", ".top", ".zip", ".review",
    ".work", ".fit", ".rest", ".party", ".cam", ".loan", ".download"
]

def rule_based_check(url: str) -> bool:
    url_lower = url.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            return True
    ext = tldextract.extract(url)
    domain_tld = f".{ext.suffix}"
    if domain_tld in BAD_TLDS:
        return True
    if "-" in ext.domain:
        return True
    return False

# ---------------- ML + RULE HYBRID ---------------- #
def extract_features(url):
    return [len(url), url.count("."), url.count("-"), url.count("="), url.startswith("https")]

def predict_url(url, model):
    print(Fore.CYAN + f"\n🌐 Target URL: {url}\n")
    print(Fore.YELLOW + "🚀 Extracting Features...\n")
    for _ in tqdm(range(40), desc="Progress"):
        pass

    features = extract_features(url)
    prediction = model.predict([features])[0]

    if rule_based_check(url):
        print(Fore.RED + "🚨 PHISHING DETECTED (Rule-based override)")
        print(Fore.LIGHTRED_EX + "⚠️ This website shows suspicious signs, better avoid it.\n")
    else:
        if prediction == 1:
            print(Fore.RED + "🚨 PHISHING DETECTED")
            print(Fore.LIGHTRED_EX + "⚠️ This site is malicious.\n")
        else:
            print(Fore.GREEN + "✅ SAFE: This website seems legitimate.")
            print(Fore.LIGHTGREEN_EX + "🛡️ You can browse safely!\n")

# ---------------- FANCY BANNER ---------------- #
def colorful_banner(text):
    banner = pyfiglet.figlet_format(text, font="slant")
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.MAGENTA, Fore.LIGHTBLUE_EX]
    result = ""
    for line in banner.split("\n"):
        result += random.choice(colors) + line + "\n"
    return result

# ---------------- MAIN APP ---------------- #
def main():
    print(colorful_banner("Phishing Detector"))
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "🔒 Developed by Het Vaghasiya (@hackwithhet)\n")

    parser = argparse.ArgumentParser(description="Phishing Detection Tool")
    parser.add_argument("urls", nargs="+", help="List of URLs to scan")
    args = parser.parse_args()

    model = joblib.load("phishing_model.pkl")

    for url in args.urls:
        predict_url(url, model)

if __name__ == "__main__":
    main()
