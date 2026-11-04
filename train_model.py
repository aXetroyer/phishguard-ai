import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score


# Project paths
BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "emails.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"

# Load dataset
df = pd.read_csv(DATA_PATH)

print("Dataset columns:", df.columns.tolist())
print("Dataset size:", df.shape)

# Adjust these names if your CSV uses different columns
TEXT_COLUMN = "Email Text"
LABEL_COLUMN = "Email Type"

# Validate columns
if TEXT_COLUMN not in df.columns or LABEL_COLUMN not in df.columns:
    raise ValueError(
        f"Expected columns '{TEXT_COLUMN}' and '{LABEL_COLUMN}'. "
        f"Found: {df.columns.tolist()}"
    )

# Prepare data
df = df[[TEXT_COLUMN, LABEL_COLUMN]].dropna()

X = df[TEXT_COLUMN].astype(str)

# Convert labels
label_mapping = {
    "Safe Email": 0,
    "Phishing Email": 1
}

y = df[LABEL_COLUMN].map(label_mapping)

if y.isna().any():
    raise ValueError(
        f"Unexpected labels: {df[LABEL_COLUMN].unique()}"
    )

y = y.astype(int)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Create machine learning pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        stop_words="english",
        max_features=10000
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ))
])

# Train
print("\nTraining model...")
model.fit(X_train, y_train)

# Evaluate
predictions = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, predictions))
print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Legitimate", "Phishing"]
))

# Save model
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(model, MODEL_PATH)

print(f"\nModel saved to: {MODEL_PATH}")
