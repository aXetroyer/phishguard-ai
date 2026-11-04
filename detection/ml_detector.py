
import os
import joblib


# Locate project root regardless of working directory
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "phishing_model.joblib"
)


def load_model():
    """Load the trained phishing detection model."""

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_PATH}. "
            "Run train_model.py first."
        )

    return joblib.load(MODEL_PATH)


def detect_phishing(email_text):
    """Classify an email using the trained ML model."""

    if not isinstance(email_text, str) or not email_text.strip():
        raise ValueError("Email text cannot be empty")

    model = load_model()

    # Predict class
    prediction = model.predict([email_text])[0]

    # Get probability for phishing class
    probabilities = model.predict_proba([email_text])[0]

    classes = list(model.classes_)

    if 1 not in classes:
        raise ValueError(
            "Model does not contain phishing class 1"
        )

    phishing_index = classes.index(1)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    return {
        "prediction": int(prediction),
        "classification": (
            "Phishing" if prediction == 1 else "Legitimate"
        ),
        "phishing_probability": phishing_probability
    }
