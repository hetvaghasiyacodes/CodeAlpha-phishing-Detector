
from urllib.parse import urlparse
import datetime as dt

try:
    import whois
except Exception:
    whois = None

def _safe_domain_from_url(url: str):
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return parsed, (parsed.netloc or parsed.path).split("/")[0]
    except Exception:
        # minimal fallback
        return urlparse("http://invalid"), ""
    
def extract_features(url: str, use_whois: bool = True):
    """
    Robust feature extractor.
    Set use_whois=False to avoid slow/fragile WHOIS lookups (fallback to 0).
    Returns a dict of numeric features.
    """
    feats = {}
    parsed, domain = _safe_domain_from_url(url)
    host = domain.lower()
    url_str = url.strip()
    
    feats["url_length"] = len(url_str)
    feats["has_https"] = 1 if parsed.scheme == "https" else 0
    feats["count_hyphen"] = url_str.count('-')
    feats["count_at"] = url_str.count('@')
    feats["count_digits"] = sum(ch.isdigit() for ch in url_str)
    feats["subdomain_count"] = host.count('.') if host else 0
    feats["has_ip_in_host"] = 1 if re_ip(host) else 0
    feats["has_suspicious_words"] = 1 if has_suspicious_words(url_str) else 0
    feats["path_length"] = len(parsed.path or "")
    feats["query_length"] = len(parsed.query or "")
    
    # WHOIS: domain age in days (optional)
    age_days = 0
    if use_whois and whois is not None and host:
        try:
            w = whois.whois(host)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                age_days = (dt.datetime.now() - creation).days
        except Exception:
            age_days = 0
    feats["domain_age"] = age_days
    
    return feats

def feature_order_example():
    # Stable column order for vectorization
    return list(extract_features("http://example.com", use_whois=False).keys())

def re_ip(host: str) -> bool:
    # Simple IPv4 check
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p):
        return True
    return False

def has_suspicious_words(s: str) -> bool:
    words = [
        "login", "verify", "update", "secure", "account", "bank", "password",
        "confirm", "billing", "invoice", "gift", "free", "bonus", "win", "unlock",
        "paypal", "appleid", "microsoft", "amazon", "support", "helpdesk"
    ]
    s_low = s.lower()
    return any(w in s_low for w in words)
