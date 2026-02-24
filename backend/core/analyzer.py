import argparse # for comamand line testing for the analyzer module
import json
import whois
import datetime
from backend.core import feature_extractor
from backend.core import ml_model 
from backend.core import virustotal
from backend.core import dns_checker

def check_whois_risk(url: str) -> tuple:
    """
    Analyzes WHOIS data for domain risk signals.
    
    Returns:
        risk_level (str)       : 'high', 'medium', 'none', or 'unknown'
        age_days (int | None)  : Domain age in days
        reasons (list)         : List of risk reason strings
        error (str | None)     : Error message if WHOIS failed
    """
    try:
        domain = url.strip().lower()
        if domain.startswith("https://"): domain = domain[8:]
        elif domain.startswith("http://"): domain = domain[7:]
        domain = domain.split("/")[0].replace("www.", "")

        if not domain:
            return "unknown", None, [], "Invalid domain"

        w = whois.whois(domain)
        reasons = []

        # Domain Age Check 
        creation_date = w.creation_date
        if not creation_date:
            return "unknown", None, [], "No creation date found in WHOIS"

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days

        if age_days < 30:
            reasons.append(f"Very new domain ({age_days} days old)")
            risk_level = "high"
        elif age_days < 90:
            reasons.append(f"Recently registered domain ({age_days} days old)")
            risk_level = "medium"
        else:
            risk_level = "none"

        # Registration Length Check 
        expiration_date = w.expiration_date
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            registered_for_days = (expiration_date - creation_date).days
            if registered_for_days < 400:  # ~1 year or less
                reasons.append("Domain registered for only ~1 year (short-term registration)")
                if risk_level == "none":
                    risk_level = "medium"

        return risk_level, age_days, reasons, None

    except Exception as e:
        return "unknown", None, [], str(e)


def analyze_url(url: str) -> dict:
    """
    NetShield Tiered Security Pipeline
    Tier 0 -> DNS Lookup (If the domain doesn't resolve, it's not real - flag as Invalid) & WHOIS Domain Age (Newly Registered Domain check)
    Tier 1 -> Local ML (Phishing)
    Tier 2 -> VirusTotal
    """
    # Tier 0 -> DNS Lookup
    resolves, ip, dns_error = dns_checker.check_dns(url)

    if not resolves:
        return {
            "url": url,
            "final_prediction": "Invalid Domain",
            "confidence": 100.0,
            "source": "DNS Check (Tier -1)",
            "risk_factors": ["Domain does not resolve in DNS"],
            "details": f"This domain has no DNS record and does not exist on the internet. {dns_error}"
        }
        
    # WHOIS Risk Check        
    
    whois_risk, age_days, whois_reasons, whois_error = check_whois_risk(url)    
    if whois_risk == "high":
        return {
            "url": url,
            "final_prediction": "Malicious",
            "confidence": 95.0, # High confidence because new domains are highly suspect
            "source": "WHOIS (Tier 0)",
            "risk_factors": whois_reasons,
            "details": "Extremely new domains are highly correlated with active phishing and malware campaigns."
        }
        
    # Medium risk reasons get carried forward and merged into ML results
    extra_risk_factors = whois_reasons if whois_risk == "medium" else []
    
    # Tier 1 -> Local ML Prediction
    features = feature_extractor.extract_features(url)
    
    prediction, confidence, reasons = ml_model.predict_url_full(url, features)
    reasons = reasons + extra_risk_factors

    confidence_percent = round(confidence * 100, 2)

    # HIGH CONFIDENCE : Skip API
    if confidence >= 0.95 or confidence <= 0.10:
        return {
            "url": url,
            "final_prediction": prediction,
            "confidence": confidence_percent,
            "source": "Local ML (Tier 1)",
            "risk_factors": reasons,
            "details": "High confidence prediction. API skipped."
        }

    
    # Tier 2 -> Virus Total API check
    vt_result = virustotal.check_virustotal(url)

    # If VirusTotal fails : fallback to ML
    if not vt_result or "error" in vt_result:
        return {
            "url": url,
            "final_prediction": prediction,
            "confidence": confidence_percent,
            "source": "Local ML (Fallback)",
            "risk_factors": reasons,
            "details": "VirusTotal unavailable. Using ML result."
        }

    # If VirusTotal has no data
    if vt_result.get("prediction") == "Unknown":
        return {
            "url": url,
            "final_prediction": prediction,
            "confidence": confidence_percent,
            "source": "Local ML (No VT Data)",
            "risk_factors": reasons,
            "details": "No reputation data found."
        }


    return {
        "url": url,
        "final_prediction": vt_result["prediction"],
        "confidence": "External Verification",
        "source": "VirusTotal (Tier 2)",
        "risk_factors": reasons,
        "details": f"{vt_result.get('malicious_flags', 0)} vendors flagged this URL."
    }



# below code is for command line analysis for this file.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetShield URL Analyzer - CLI Testing")
    parser.add_argument("-u", "--url", required=True, help="The URL string you want to analyze")
    args = parser.parse_args()
    
    print(f"\n[NetShield] Analyzing URL: {args.url}")
    print("-" * 60)
    result = analyze_url(args.url)
    print(json.dumps(result, indent=4))
    print("-" * 60)