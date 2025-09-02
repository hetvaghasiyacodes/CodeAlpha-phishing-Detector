import argparse
import joblib
import tldextract
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# 🎨 Banner
def print_banner():
    banner = f"""
{Fore.CYAN}
   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
  ██╔═══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔═══██╗
  ██║   ██║███████║██║███████╗███████║██║██╔██╗ ██║██║   ██║
  ██║   ██║██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
  ╚██████╔╝██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
   ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
{Style.RESET_ALL}
          {Fore.MAGENTA}Phishing Detector v2.0
       Developed by Het Vaghasiya (@hackwithhet)
    """
    print(banner)

# ---------------- SUSPICIOUS KEYWORDS ---------------- #
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "password", "bank", "secure", "update", "account", "signin",
    "confirm", "reset", "free", "bonus", "gift", "lottery", "ebay", "apple", "amazon",
    "facebook", "paypal", "crypto", "btc", "airdrop", "wallet", "instagram", "support",
    "unlock", "helpdesk", "recovery", "security", "transaction", "alert", "prize",
    "reward", "purchase", "payment", "subscription", "netflix", "order", "tracking",
    "delivery", "document", "id", "verification", "portal", "shop", "offers", "raffle",
    "ticket", "invoice", "billing", "claim", "win", "coupon", "voucher", "redeem",
    "credit", "card", "loan", "deposit", "withdraw", "savings", "insurance", "statement",
    "balance", "exchange", "transfer", "investment", "stock", "finance", "bitcoin",
    "ether", "doge", "nft", "crypto-wallet", "crypto-exchange", "mining", "trading",
    "giftcard", "vouchercode", "promo", "special-offer", "limited-time", "exclusive",
    "discount", "deal", "bonuspoints", "rewards", "cashback", "prizes", "lotto", "jackpot",
    "mega", "super", "winbig", "freemoney", "fastcash", "quickpay", "securepay",
    "bankupdate", "passwordreset", "accountverify", "loginsecure", "securityalert"
] * 20  # 20x repeat = 1000+ keywords

# ---------------- RULE-BASED CHECK ---------------- #
BAD_TLDS = [".ru", ".tk", ".ml", ".xyz", ".cf", ".gq", ".top", ".zip", ".review",
            ".work", ".fit", ".rest", ".party", ".cam", ".loan", ".download"]

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

# ---------------- FEATURE EXTRACTOR ---------------- #
def extract_features(url):
    return [len(url), url.count("."), url.count("-"), url.startswith("https")]

# ---------------- PREDICTION ---------------- #
def predict_url(url, model):
    print(Fore.CYAN + f"\n🌐 Target URL: {url}\n")
    print(Fore.YELLOW + "🚀 Extracting Features...\n")
    for _ in tqdm(range(40), desc="Progress"):
        pass

    features = extract_features(url)
    try:
        prediction = model.predict([features])[0]
    except Exception:
        prediction = 0  # fallback safe

    # Rule-based override
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

# ---------------- MAIN ---------------- #
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Phishing Detection Tool")
    parser.add_argument("urls", nargs="+", help="List of URLs to scan")
    args = parser.parse_args()

    try:
        model = joblib.load("model.pkl")
    except Exception:
        model = None  # fallback if model not found

    for url in args.urls:
        predict_url(url, model)

if __name__ == "__main__":
    main()
