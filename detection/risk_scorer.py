
def calculate_risk(
    ml_probability,
    email_findings=None,
    url_findings=None
):
    """
    Calculate an illustrative email risk score.

    ml_probability: ML phishing probability (0.0 - 1.0)
    email_findings: List of email security indicators
    url_findings: URL analysis results
    """

    email_findings = email_findings or []
    url_findings = url_findings or {}

    # Validate ML probability
    if not isinstance(ml_probability, (int, float)):
        raise TypeError("ML probability must be numeric")

    if not 0 <= ml_probability <= 1:
        raise ValueError("ML probability must be between 0 and 1")

    # ML contribution: maximum 60 points
    score = ml_probability * 60

    # Email indicator contribution
    email_weights = {
        "urgent_language": 8,
        "credential_request": 12,
        "sender_mismatch": 12,
        "suspicious_attachment": 8
    }

    for finding in email_findings:
        score += email_weights.get(finding, 0)

    # URL indicator contribution
    results = url_findings.get("results", [])

    for result in results:
        if result.get("suspicious"):
            score += 10

    # Keep score within 0-100
    score = min(round(score), 100)

    # Assign risk category
    if score >= 70:
        category = "High"
    elif score >= 40:
        category = "Medium"
    else:
        category = "Low"

    return {
        "risk_score": score,
        "risk_category": category,
        "ml_probability": round(ml_probability, 4),
        "email_indicators": email_findings,
        "url_indicators": results
    }
