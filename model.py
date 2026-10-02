import os
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

import joblib


# =========================================================
# CONFIGURATION
# =========================================================

DATASET_FILE = "PhiUSIIL_Phishing_URL_Dataset.csv"

MODEL_FILE = "url_threat_model.pkl"
VECTORIZER_FILE = "url_vectorizer.pkl"


# =========================================================
# TRAIN MODEL
# =========================================================

def train_model():

    print("📂 Loading dataset...")

    data = pd.read_csv(DATASET_FILE)

    data = data[
        ["URL", "label"]
    ].dropna()

    X = data["URL"].astype(str)
    y = data["label"]

    print("✅ Dataset loaded successfully!")
    print(f"📊 Total URLs: {len(data)}")

    # -----------------------------------------------------
    # TRAIN / TEST SPLIT
    # -----------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    # -----------------------------------------------------
    # URL FEATURE EXTRACTION
    # -----------------------------------------------------

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        max_features=50000
    )

    X_train_vectorized = vectorizer.fit_transform(
        X_train
    )

    X_test_vectorized = vectorizer.transform(
        X_test
    )

    print("🔄 URL features created successfully!")

    # -----------------------------------------------------
    # TRAIN LOGISTIC REGRESSION
    # -----------------------------------------------------

    model = LogisticRegression(
        max_iter=1000
    )

    model.fit(
        X_train_vectorized,
        y_train
    )

    print("🤖 AI model trained successfully!")

    # -----------------------------------------------------
    # MODEL EVALUATION
    # -----------------------------------------------------

    predictions = model.predict(
        X_test_vectorized
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print(
        f"📊 Model accuracy: "
        f"{accuracy * 100:.2f}%"
    )

    # -----------------------------------------------------
    # SAVE MODEL
    # -----------------------------------------------------

    joblib.dump(
        model,
        MODEL_FILE
    )

    joblib.dump(
        vectorizer,
        VECTORIZER_FILE
    )

    print(
        "💾 AI model saved successfully!"
    )

    return model, vectorizer


# =========================================================
# LOAD MODEL
# =========================================================

def load_model():

    if (
        os.path.exists(MODEL_FILE)
        and
        os.path.exists(VECTORIZER_FILE)
    ):

        model = joblib.load(
            MODEL_FILE
        )

        vectorizer = joblib.load(
            VECTORIZER_FILE
        )

        return model, vectorizer

    print(
        "⚠️ Saved AI model not found."
    )

    print(
        "🔄 Training the model for the first time..."
    )

    return train_model()


# =========================================================
# LOAD AI MODEL
# =========================================================

model, vectorizer = load_model()


# =========================================================
# URL PREDICTION
# =========================================================

def predict_url(url):

    url = str(url).strip()

    if not url:

        return (
            "Potentially Malicious",
            100.0
        )

    url_vectorized = vectorizer.transform(
        [url]
    )

    prediction = model.predict(
        url_vectorized
    )[0]

    probabilities = model.predict_proba(
        url_vectorized
    )[0]

    # =====================================================
    # PHIUSIIL LABEL MAPPING
    #
    # 1 = Legitimate
    # 0 = Phishing
    # =====================================================

    if prediction == 0:

        result = "Potentially Malicious"

        confidence = (
            probabilities[
                list(model.classes_).index(0)
            ] * 100
        )

    else:

        result = "Likely Legitimate"

        confidence = (
            probabilities[
                list(model.classes_).index(1)
            ] * 100
        )

    return (
        result,
        confidence
    )


# =========================================================
# DIRECT EXECUTION
# =========================================================

if __name__ == "__main__":

    print()
    print("=" * 55)
    print("🛡️ AI CYBER THREAT ANALYSIS - URL MODEL")
    print("=" * 55)
    print()

    print(
        "✅ Model is ready for URL prediction."
    )

    print()

    test_url = input(
        "🔗 Enter a URL to analyze: "
    ).strip()

    if test_url:

        result, confidence = predict_url(
            test_url
        )

        print()
        print("🔎 Analysis Result")
        print("-" * 30)
        print(
            f"Classification : {result}"
        )
        print(
            f"AI Confidence  : {confidence:.2f}%"
        )
        print()