"""
Step 2: Train a message-risk classifier.

WHAT THIS SCRIPT DOES (in plain terms):

1. Splits the data into a training set (model learns from this) and a test set
   (model has never seen this — used to check if it actually learned something
   useful, not just memorised the training data).

2. Converts text into numbers using TF-IDF.
   TF-IDF = "Term Frequency - Inverse Document Frequency". In simple words:
   it looks at every word in every message and scores each word by
   "how often does this word show up in THIS message" vs "how common is
   this word across ALL messages". Words like "free", "win", "urgent",
   "prize" get high scores in spam because they're common in spam but rare
   in normal chat. Words like "the", "is", "and" get low scores everywhere.

3. Trains a Logistic Regression model on those scores.
   Logistic Regression is a simple, well-understood classifier that's a
   good starting point before jumping to something heavier like BERT ---
   it's fast to train, easy to explain in a viva, and works well for this
   kind of text classification.

4. Handles the class imbalance (only 13% spam) using class_weight="balanced",
   which tells the model "pay more attention to the minority class (spam)
   instead of just predicting 'ham' every time to get a high accuracy".

5. Evaluates using precision, recall, F1-score --- these matter more than
   plain accuracy here (a model that always says "ham" would be 87%
   "accurate" and still useless).

Run it with:  python 2_train_model.py
"""

import json
import pandas as pd
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score, f1_score

BASE_DIR = Path(__file__).resolve().parent.parent  # the upi-fraud-system folder
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA_DIR / "messages_clean.csv")

X = df["message"]
y = df["target"]

# 80% train, 20% test. stratify=y keeps the same spam/ham ratio in both splits.
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training on {len(X_train)} messages, testing on {len(X_test)} messages\n")

# --- Text -> numbers ---
vectorizer = TfidfVectorizer(
    lowercase=True,       # "FREE" and "free" should count the same
    stop_words="english", # ignore common filler words (the, is, and...)
    max_features=3000,    # keep only the 3000 most informative words
    ngram_range=(1, 2),   # look at single words AND pairs of words (e.g. "act now")
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# --- Train the model ---
model = LogisticRegression(
    class_weight="balanced",  # compensate for spam being only ~13% of the data
    max_iter=1000,
    random_state=42,
)
model.fit(X_train_vec, y_train)

# --- Evaluate ---
y_pred = model.predict(X_test_vec)
y_proba = model.predict_proba(X_test_vec)[:, 1]  # probability of being spam

print("=== Classification report ===")
print(classification_report(y_test, y_pred, target_names=["ham (safe)", "spam (risky)"]))

print("=== Confusion matrix ===")
cm = confusion_matrix(y_test, y_pred)
print(f"                 predicted ham   predicted spam")
print(f"actual ham          {cm[0][0]:>5}           {cm[0][1]:>5}")
print(f"actual spam         {cm[1][0]:>5}           {cm[1][1]:>5}")

print(f"\nROC-AUC score: {roc_auc_score(y_test, y_proba):.4f}  (1.0 = perfect, 0.5 = random guessing)")

# --- Save the trained model + vectorizer for later use ---
joblib.dump(model, MODELS_DIR / "nlp_model.joblib")
joblib.dump(vectorizer, MODELS_DIR / "nlp_vectorizer.joblib")
metrics = {
    "model": "TF-IDF + Logistic Regression",
    "test_samples": int(len(y_test)),
    "precision": round(float(precision_score(y_test, y_pred)), 4),
    "recall": round(float(recall_score(y_test, y_pred)), 4),
    "f1_score": round(float(f1_score(y_test, y_pred)), 4),
    "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
}
(MODELS_DIR / "nlp_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
print("\nSaved model to models/nlp_model.joblib")
print("Saved vectorizer to models/nlp_vectorizer.joblib")
print("Saved evaluation metrics to models/nlp_metrics.json")
