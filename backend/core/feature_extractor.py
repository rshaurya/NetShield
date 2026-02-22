import re
import math
from urllib.parse import urlparse
from collections import Counter




def normalize_url(url: str) -> str:
    """Remove scheme and strip spaces"""
    url = url.strip().lower()
    if url.startswith("https://"):
        url = url[8:]
    elif url.startswith("http://"):
        url = url[7:]
    return url


def calculate_entropy(string: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not string:
        return 0.0

    counter = Counter(string)
    length = len(string)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )

    return round(entropy, 4)


FEATURE_ORDER = [
    # Length features
    "url_length",
    "domain_length",
    "path_length",

    # Count features
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "slash_count",
    "question_count",
    "equal_count",
    "at_count",
    "percent_count",
    "digit_count",

    # Binary flags
    "has_ip",
    "has_at_symbol",
    "has_double_slash",
    "has_prefix_suffix",

    # Entropy
    "domain_entropy",
    "url_entropy",

    # Structural features
    "subdomain_count",
    "url_depth",


    "contains_suspicious_keyword",
    "risky_tld",
    "many_hyphens",
    "deep_subdomain",
    "long_domain_flag",
    "trusted_tld",
    
    
]



def extract_features(url: str) -> dict:
    url = normalize_url(url)

    try:
        parsed = urlparse("http://" + url)
        domain = parsed.netloc
        path = parsed.path
        

        tld = "." + domain.split(".")[-1]

        risky_tlds = [".ru", ".cn", ".tk", ".ml", ".ga"]

        risky_tld_flag = 1 if tld in risky_tlds else 0


        suspicious_keywords = [
            "login", "verify", "secure", "update",
            "account", "bank", "paypal", "signin",
            "confirm", "webscr"
        ]

        contains_suspicious = 1 if any(
            word in url for word in suspicious_keywords
        ) else 0

        risky_tlds = [".ru", ".cn", ".tk", ".ml", ".ga"]

        risky_tld_flag = 1 if any(
            domain.endswith(tld) for tld in risky_tlds
        ) else 0
        
        trusted_tlds = [".edu", ".ac.in", ".gov", ".org"]

        trusted_tld_flag = 1 if any(
            domain.endswith(tld) for tld in trusted_tlds
        ) else 0


        features = {
            # Length
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),

            # Counts
            "dot_count": url.count("."),
            "hyphen_count": url.count("-"),
            "underscore_count": url.count("_"),
            "slash_count": url.count("/"),
            "question_count": url.count("?"),
            "equal_count": url.count("="),
            "at_count": url.count("@"),
            "percent_count": url.count("%"),
            "digit_count": sum(c.isdigit() for c in url),

            # Binary flags
            "has_ip": 1 if re.match(r"(\d{1,3}\.){3}\d{1,3}", domain) else 0,
            "has_at_symbol": 1 if "@" in url else 0,
            "has_double_slash": 1 if "//" in path else 0,
            "has_prefix_suffix": 1 if "-" in domain else 0,

            # Entropy
            "domain_entropy": calculate_entropy(domain),
            "url_entropy": calculate_entropy(url),

            # Structural
            "subdomain_count": max(len(domain.split(".")) - 2, 0),
            "url_depth": len([p for p in path.split("/") if p]),


            "contains_suspicious_keyword": contains_suspicious,
            "risky_tld": risky_tld_flag,
            "trusted_tld": trusted_tld_flag,
            "many_hyphens": 1 if domain.count("-") >= 2 else 0,
            "deep_subdomain": 1 if max(len(domain.split(".")) - 2, 0) >= 2 else 0,
            "long_domain_flag": 1 if len(domain) > 25 else 0,
            
            
        }

        return features

    except Exception:
        return {key: 0 for key in FEATURE_ORDER}


def features_to_list(features: dict) -> list:
    """Convert feature dictionary to ordered list for ML model"""
    return [features[key] for key in FEATURE_ORDER]