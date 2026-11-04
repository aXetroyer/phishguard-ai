
from detection.url_analyzer import analyze_email_urls
from detection.risk_scorer import calculate_risk

# Test URL analyzer
email = """
Your account needs verification.
Please visit https://192.0.2.10/login
"""

url_results = analyze_email_urls(email)

print("URL ANALYSIS:")
print(url_results)

# Test risk scorer
risk_results = calculate_risk(
    ml_probability=0.85,
    email_findings=[
        "urgent_language",
        "credential_request"
    ],
    url_findings=url_results
)

print("\nRISK ASSESSMENT:")
print(risk_results)

assert 0 <= risk_results["risk_score"] <= 100

print("\nBasic tests completed!")
