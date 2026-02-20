import sys
sys.path.append("D:/NetShield")

from backend.core.analyzer import analyze_url

test_urls = [
    "https://google.com",
    "https://paypal-secure-login.suspicious-site.com/verify",
    "http://192.168.1.1/malware/download",
    "https://facebook.com",
    "https://totally-fake-paypal.ru/login",
    "https://vtop.vitbhopal.ac.in",
]

print("\n========== NetShield Full Pipeline Test ==========\n")

for url in test_urls:
    print(f"Testing URL: {url}")
    print("-" * 60)

    result = analyze_url(url)

    print(f"Final Prediction : {result['final_prediction']}")
    print(f"Source           : {result['source']}")

    if isinstance(result.get("confidence"), (int, float)):
        print(f"Confidence       : {result['confidence']:.2f}%")
    else:
        print(f"Confidence       : {result['confidence']}")

    print(f"Details          : {result.get('details', 'N/A')}")
    print("-" * 60)
    print()

print("=============== Test Complete ===============")