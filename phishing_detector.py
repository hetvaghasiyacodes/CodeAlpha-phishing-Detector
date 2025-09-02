import sys
import re
import tldextract
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

# ========== 🎨 Banner ==========
def banner():
    print(Fore.CYAN + r"""
    ____  __    _      __    _               
   / __ \/ /_  (_)____/ /_  (_)___  ____ _   
  / /_/ / __ \/ / ___/ __ \/ / __ \/ __ `/   
 / ____/ / / / (__  ) / / / / / / / /_/ /    
/_/   /_/ /_/_/____/_/ /_/_/_/ /_/\__, /     
                                 /____/      
    ____       __            __              
   / __ \___  / /____  _____/ /_____  _____  
  / / / / _ \/ __/ _ \/ ___/ __/ __ \/ ___/  
 / /_/ /  __/ /_/  __/ /__/ /_/ /_/ / /      
/_____/\___/\__/\___/\___/\__/\____/_/       
                                            
""" + Style.RESET_ALL)
    print(Fore.GREEN + "🔒 Human-Logic Phishing Detector by Het\n" + Style.RESET_ALL)


# ========== 🔍 Human Logic Detection ==========
def check_url(url: str):
    score = 0
    reasons = []

    # 1. Length check
    if len(url) > 75:
        score += 1
        reasons.append("URL is too long")

    # 2. '@' symbol
    if "@" in url:
        score += 2
        reasons.append("Contains '@' symbol")

    # 3. '-' in domain
    if "-" in urlparse(url).netloc:
        score += 1
        reasons.append("Domain contains '-'")

    # 4. Count of digits
    if sum(c.isdigit() for c in url) > 5:
        score += 1
        reasons.append("Too many numbers in URL")

    # 5. Suspicious keywords
    suspicious_words = [
        "login", "secure", "update", "banking", "verify",
        "account", "paypal", "signin", "ebay", "amazon",
        "wallet", "support", "confirm", "password", "checkout"
    ]
    if any(word in url.lower() for word in suspicious_words):
        score += 2
        reasons.append("Suspicious keyword found")

    # 6. IP address instead of domain
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}", urlparse(url).netloc):
        score += 2
        reasons.append("Uses IP instead of domain")

    # 7. HTTPS check
    if not url.lower().startswith("https://"):
        score += 1
        reasons.append("Does not use HTTPS")

    return score, reasons


# ========== 🚀 Main ==========
def main():
    banner()

    if len(sys.argv) != 2:
        print(Fore.YELLOW + "⚠️ Usage: python phishing_detector.py <URL>" + Style.RESET_ALL)
        sys.exit(1)

    url = sys.argv[1]

    # Validate URL format
    if not url.lower().startswith(("http://", "https://")):
        print(Fore.RED + "❌ Invalid URL! Must start with http:// or https://" + Style.RESET_ALL)
        sys.exit(1)

    # Analyse URL
    score, reasons = check_url(url)

    # Result
    if score >= 4:
        print(Fore.RED + f"\n🚨 ALERT: '{url}' looks like a PHISHING site!" + Style.RESET_ALL)
    elif score >= 2:
        print(Fore.YELLOW + f"\n⚠️ WARNING: '{url}' is suspicious. Be careful." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + f"\n✅ SAFE: '{url}' seems legitimate." + Style.RESET_ALL)

    # Explain reasons
    if reasons:
        print(Fore.CYAN + "\n📌 Reasons:")
        for r in reasons:
            print(" - " + r)


if __name__ == "__main__":
    main()
