
import streamlit as st

from detection.ml_detector import detect_phishing
from detection.url_analyzer import analyze_email_urls
from detection.risk_scorer import calculate_risk


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide"
)


# ==================================================
# CUSTOM CSS
# ==================================================

st.markdown("""
<style>

.stApp {
    background-color: #101827;
    color: #E5E7EB;
}

h1, h2, h3 {
    color: #60A5FA;
}

div[data-testid="stMetric"] {
    background-color: #1E293B;
    padding: 18px;
    border-radius: 10px;
}

.stTextArea textarea {
    background-color: #1E293B;
    color: white;
}

div.stButton > button {
    border-radius: 8px;
    font-weight: bold;
}

</style>
""", unsafe_allow_html=True)


# ==================================================
# HEADER
# ==================================================

st.title("🛡️ PhishGuard AI")

st.caption(
    "AI-powered phishing detection and email threat analysis"
)

st.divider()


# ==================================================
# EMAIL INPUT
# ==================================================

st.subheader("📧 Email Analysis")

email_text = st.text_area(
    "Paste an email to analyze:",
    height=250,
    placeholder="""Paste an email here...

Example:
Subject: Urgent Account Verification

Your account requires immediate verification.
Please visit https://example.com/login
to verify your credentials.
"""
)

analyze_button = st.button(
    "🔍 Analyze Email",
    type="primary",
    use_container_width=True
)


# ==================================================
# ANALYSIS
# ==================================================

if analyze_button:

    if not email_text.strip():

        st.warning("Please enter an email before analyzing.")

    else:

        try:

            with st.spinner("Analyzing email..."):

                # Machine learning detection
                ml_results = detect_phishing(email_text)

                # URL analysis
                url_results = analyze_email_urls(email_text)

                # Risk scoring
                risk_results = calculate_risk(
                    ml_probability=ml_results["phishing_probability"],
                    url_findings=url_results
                )

            st.divider()

            st.header("📊 Analysis Results")


            # ==================================================
            # METRICS
            # ==================================================

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric(
                    "Classification",
                    ml_results["classification"]
                )

            with col2:

                st.metric(
                    "Risk Score",
                    f'{risk_results["risk_score"]}/100'
                )

            with col3:

                st.metric(
                    "Risk Level",
                    risk_results["risk_category"]
                )


            # ==================================================
            # RISK STATUS
            # ==================================================

            category = risk_results["risk_category"]

            if category == "High":

                st.error(
                    "⚠️ High-risk email detected. "
                    "This email contains multiple warning indicators."
                )

            elif category == "Medium":

                st.warning(
                    "⚠️ Potentially suspicious email. "
                    "Review the detected indicators carefully."
                )

            else:

                st.success(
                    "No major warning indicators detected."
                )


            # ==================================================
            # MACHINE LEARNING RESULTS
            # ==================================================

            st.subheader("🤖 Machine Learning Results")

            probability = ml_results["phishing_probability"]

            st.write(
                f"Phishing probability: {probability:.1%}"
            )

            st.progress(float(probability))


            # ==================================================
            # URL ANALYSIS
            # ==================================================

            st.subheader("🔗 URL Analysis")

            st.write(
                f"URLs found: {url_results['total_urls']}"
            )

            st.write(
                f"Suspicious URLs: {url_results['suspicious_urls']}"
            )

            if not url_results["results"]:

                st.info("No URLs were found in this email.")

            for result in url_results["results"]:

                with st.expander(result["url"]):

                    if result["suspicious"]:

                        st.error("Suspicious indicators detected.")

                    else:

                        st.success("No suspicious indicators detected.")

                    findings = result.get("findings", [])

                    if findings:

                        st.write("Detected indicators:")

                        for finding in findings:

                            st.markdown(f"- ⚠️ {finding}")

                    else:

                        st.write("No URL warning indicators detected.")


            # ==================================================
            # THREAT INDICATORS
            # ==================================================

            st.subheader("🚨 Threat Indicators")

            email_indicators = risk_results.get(
                "email_indicators", []
            )

            url_indicators = risk_results.get(
                "url_indicators", []
            )

            # Email indicators
            if email_indicators:

                st.markdown("**Email indicators:**")

                for indicator in email_indicators:

                    formatted_indicator = str(indicator).replace(
                        "_", " "
                    ).title()

                    st.markdown(
                        f"- ⚠️ {formatted_indicator}"
                    )


            # URL indicators
            if url_indicators:

                st.markdown("**URL indicators:**")

                for url_result in url_indicators:

                    if isinstance(url_result, dict):

                        url = url_result.get(
                            "url", "Unknown URL"
                        )

                        findings = url_result.get(
                            "findings", []
                        )

                        st.markdown(f"**URL:** `{url}`")

                        if findings:

                            for finding in findings:

                                st.markdown(
                                    f"- ⚠️ {finding}"
                                )

                        else:

                            st.markdown(
                                "- No suspicious indicators reported."
                            )

                    else:

                        st.markdown(
                            f"- ⚠️ {url_result}"
                        )


            # No additional indicators
            if not email_indicators and not url_indicators:

                st.success(
                    "No additional rule-based indicators were detected."
                )


            # ==================================================
            # DISCLAIMER
            # ==================================================

            st.divider()

            st.caption(
                "PhishGuard AI provides an automated assessment. "
                "A low-risk result does not guarantee that an email is safe."
            )


        # ==================================================
        # ERROR HANDLING
        # ==================================================

        except FileNotFoundError as error:

            st.error(f"Model file not found: {error}")

        except Exception as error:

            st.error(f"Analysis failed: {error}")


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.caption(
    "PhishGuard AI | Cybersecurity Portfolio Project"
)
