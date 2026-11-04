
# 🛡️ PhishGuard AI

An AI-powered phishing email detection and threat analysis platform built with Python and Streamlit.

## Overview

PhishGuard AI analyzes email content to identify potential phishing attempts using machine learning and rule-based security checks.

## Features

- Machine learning phishing classification
- TF-IDF text processing
- Logistic Regression classifier
- Suspicious URL detection
- URL indicator analysis
- Automated risk scoring
- Interactive Streamlit dashboard

## Technology Stack

- Python
- Scikit-learn
- Pandas
- Streamlit
- Joblib

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/PhishGuard-AI.git
cd PhishGuard-AI
```

Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Training

Place your properly formatted dataset at:

`data/emails.csv`

Train the model:

```bash
python train_model.py
```

## Running the Dashboard

```bash
streamlit run app.py
```

## Disclaimer

PhishGuard AI is an educational cybersecurity project. Its classifications and risk scores are not guarantees that an email is malicious or safe.
