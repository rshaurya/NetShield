import argparse # For command line interface (lack of frontend, we can test via CLI)
import json

from feature_extractor import extract_features
from ml_model import predict_url
from virustotal import check_virustotal

def analyze_url(url: str) -> dict:
    """
    The main Tiered Analysis pipeline.
    """
    # 1. Extract lexical features using predefined function
    features = extract_features(url)
    
    # 2. Get local machine learning prediction
    ml_prediction, confidence_score = predict_url(features)
    
    # 3. The Confidence Gate Logic
    if confidence_score > 0.60:
        # High Certainty: Return the local ML result
        return {
            "url": url,
            "final_prediction": ml_prediction,
            "confidence": round(confidence_score * 100, 2),
            "source": "Local ML (NetShield Tier 1)",
            "details": "Model confidence was high enough to skip API call."
        }
    else:
        # Low Certainty: Fallback to External Threat Intelligence
        vt_result = check_virustotal(url)
        
        # If VT fails or has no data, we fallback to the uncertain ML prediction
        if "error" in vt_result or vt_result.get("prediction") == "Unknown":
            return {
                "url": url,
                "final_prediction": ml_prediction,
                "confidence": round(confidence_score * 100, 2),
                "source": "Local ML (Fallback)",
                "details": f"API check failed or had no data. Relying on uncertain ML prediction. API Note: {vt_result.get('message', 'N/A')}"
            }
            
        return {
            "url": url,
            "final_prediction": vt_result["prediction"],
            "confidence": "N/A (External Verification)",
            "source": "VirusTotal API (NetShield Tier 2)",
            "details": f"Flagged as malicious by {vt_result['malicious_flags']} out of {vt_result['total_scans']} security vendors."
        }

# Command Line Interface (CLI) configuration
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetShield URL Analyzer - CLI Testing")
    parser.add_argument("-u", "--url", required=True, help="The URL string you want to analyze")
    args = parser.parse_args()
    
    print(f"\n[NetShield] Analyzing URL: {args.url}")
    print("-" * 50)
    
    # Run the analysis
    result = analyze_url(args.url)
    
    # Print the result nicely formatted as JSON
    print(json.dumps(result, indent=4))
    print("-" * 50)