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
import sys
import pandas as pd
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score, f1_score

BASE_DIR = Path(__file__).resolve().parent.parent  # the upi-fraud-system folder
sys.path.insert(0, str(BASE_DIR))
from multilingual_message_rules import analyse_multilingual_message, is_explicitly_safe_context

DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA_DIR / "messages_clean.csv")
additions_path = DATA_DIR / "message_training_additions.csv"
additions = pd.read_csv(additions_path) if additions_path.exists() else pd.DataFrame(columns=["target", "message"])
multilingual_path = DATA_DIR / "multilingual_training_subset.csv"
multilingual = pd.read_csv(multilingual_path) if multilingual_path.exists() else pd.DataFrame(columns=["target", "message", "language", "source_dataset"])
marathi_supplement_path = DATA_DIR / "marathi_synthetic_supplement.csv"
marathi_supplement = pd.read_csv(marathi_supplement_path) if marathi_supplement_path.exists() else pd.DataFrame(columns=["target", "message", "language", "source_dataset"])
marathi_translated_path = DATA_DIR / "marathi_translated_training.csv"
marathi_translated = pd.read_csv(marathi_translated_path) if marathi_translated_path.exists() else pd.DataFrame(columns=["target", "message", "language", "source_dataset"])

X = df["message"].astype(str)
y = df["target"].astype(int)

# Keep the original SMS corpus as an untouched evaluation set. The curated
# UPI examples are added to training only, preventing near-duplicate
# synthetic phrases from leaking across the train/test boundary.
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
training_rows = pd.DataFrame({
    "message": X_train.astype(str).to_numpy(),
    "target": y_train.astype(int).to_numpy(),
    "language": "English",
})
if len(additions):
    additions = additions.dropna(subset=["message", "target"])
    additions["target"] = additions["target"].astype(int)
    if "language" not in additions:
        additions["language"] = "English"
    additions["language"] = additions["language"].fillna("English").astype(str)
    training_rows = pd.concat([
        training_rows,
        additions[["message", "target", "language"]].assign(
            message=additions["message"].astype(str)
        ),
    ], ignore_index=True)
if len(multilingual):
    multilingual = multilingual.dropna(subset=["message", "target"])
    multilingual["target"] = multilingual["target"].astype(int)
    training_rows = pd.concat([
        training_rows,
        multilingual[["message", "target", "language"]].assign(
            message=multilingual["message"].astype(str),
            language=multilingual["language"].astype(str).str.title(),
        ),
    ], ignore_index=True)
if len(marathi_supplement):
    marathi_supplement = marathi_supplement.dropna(subset=["message", "target"])
    marathi_supplement["target"] = marathi_supplement["target"].astype(int)
    training_rows = pd.concat([
        training_rows,
        marathi_supplement[["message", "target", "language"]].assign(
            message=marathi_supplement["message"].astype(str),
            language="Marathlish",
        ),
    ], ignore_index=True)
if len(marathi_translated):
    marathi_translated = marathi_translated.dropna(subset=["message", "target"])
    marathi_translated["target"] = marathi_translated["target"].astype(int)
    training_rows = pd.concat([
        training_rows,
        marathi_translated[["message", "target"]].assign(
            message=marathi_translated["message"].astype(str),
            language="Marathi",
        ),
    ], ignore_index=True)

# Treat Marathlish examples as Marathi coverage and apply the same explicit
# language-bucket weights as native-script Marathi. English corpus size must
# not make English dominate the multilingual classifier's loss function.
training_rows["language_bucket"] = training_rows["language"].str.strip().str.title().replace({
    "Marathlish": "Marathi",
})
expected_buckets = {"English", "Hindi", "Marathi", "Hinglish"}
unexpected = set(training_rows["language_bucket"].unique()) - expected_buckets
if unexpected:
    raise ValueError(f"Unmapped training language labels: {sorted(unexpected)}")
language_counts = training_rows.groupby("language_bucket").size()
language_class_counts = training_rows.groupby(["language_bucket", "target"]).size()
if set(language_counts.index) != expected_buckets:
    raise ValueError("Each training language bucket must have examples before weighting")
if any((bucket, label) not in language_class_counts.index for bucket in expected_buckets for label in (0, 1)):
    raise ValueError("Each language bucket must include both safe and risky examples")

# Each language contributes 25% of total sample weight. Keep the observed
# safe/risky class proportions within each language instead of forcing a
# 50/50 class prior; class balancing had increased false alerts. Normalize to
# mean weight 1 so Logistic Regression regularization remains on a normal scale.
sample_weights = training_rows.apply(
    lambda row: 1.0 / (len(expected_buckets) * language_counts.loc[row["language_bucket"]]),
    axis=1,
).to_numpy()
sample_weights *= len(sample_weights) / sample_weights.sum()
X_train = training_rows["message"].astype(str)
y_train = training_rows["target"].astype(int)

print(
    f"Training on {len(X_train)} messages "
        f"({len(df) - len(X_test)} original + {len(additions)} curated UPI + "
        f"{len(multilingual)} external multilingual + {len(marathi_supplement)} Marathlish synthetic + "
        f"{len(marathi_translated)} Marathi machine-translated examples), "
    f"testing on {len(X_test)} untouched original messages\n"
)
print("Equal language weighting (each 25% of loss; natural safe/risky proportions retained):")
for bucket in sorted(expected_buckets):
    selected = training_rows[training_rows["language_bucket"] == bucket]
    risky_share = float(selected["target"].mean())
    print(f"  {bucket}: {len(selected)} rows; weight share={sample_weights[selected.index].sum() / sample_weights.sum():.1%}; risky labels={risky_share:.1%}")

# Word features learn scam phrases; character features help with spelling
# variations, joined words, and light obfuscation. Keep negation words in the
# vocabulary ("not", "never", "no") so safety warnings aren't erased.
vectorizer = FeatureUnion(
    [
        ("word", TfidfVectorizer(
            lowercase=True, max_features=12000, ngram_range=(1, 2),
            sublinear_tf=True, min_df=2,
        )),
        ("char", TfidfVectorizer(
            lowercase=True, analyzer="char_wb", max_features=20000,
            ngram_range=(3, 5), sublinear_tf=True, min_df=2,
        )),
    ],
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# --- Train the model ---
model = LogisticRegression(
    max_iter=1000,
    random_state=42,
)
model.fit(X_train_vec, y_train, sample_weight=sample_weights)

# --- Evaluate ---
y_proba = model.predict_proba(X_test_vec)[:, 1]  # probability of being spam
y_pred = (y_proba >= 0.5).astype(int)
combined_scores = []
for text, raw_score in zip(X_test, y_proba):
    message = str(text)
    if is_explicitly_safe_context(message):
        raw_score = min(float(raw_score), 0.22)
    rule_score, _ = analyse_multilingual_message(message)
    combined_scores.append(max(float(raw_score), rule_score or 0.0))
combined_scores = pd.Series(combined_scores, index=y_test.index)
y_pred_notification = (combined_scores >= 0.3).astype(int)

print("=== Untouched original test set, model threshold 0.50 ===")
print(classification_report(y_test, y_pred, target_names=["ham (safe)", "spam (risky)"]))
print("=== Same test set, combined API scoring at notification threshold 0.30 ===")
print(classification_report(y_test, y_pred_notification, target_names=["ham (safe)", "spam (risky)"]))

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
    "model": "Word + character TF-IDF + Logistic Regression",
    "training_original_messages": int(len(df) - len(X_test)),
    "training_curated_upi_examples": int(len(additions)),
    "training_multilingual_examples": int(len(multilingual)),
    "training_marathlish_synthetic_examples": int(len(marathi_supplement)),
    "training_marathi_machine_translated_examples": int(len(marathi_translated)),
    "marathi_machine_translation_note": "Supplemental training only; machine-translated from English SMS, not native-speaker-reviewed, with source-message-grouped holdout evaluation.",
    "language_weighting": "equal: English, Hindi, Marathi (including Marathlish), and Hinglish each contribute 25% of classifier loss; each language retains its observed safe/risky label proportions",
    "training_language_bucket_rows": {
        bucket: int(count)
        for bucket, count in training_rows.groupby("language_bucket").size().items()
    },
    "training_language_bucket_weight_share": {
        bucket: round(float(sample_weights[training_rows["language_bucket"].to_numpy() == bucket].sum() / sample_weights.sum()), 4)
        for bucket in sorted(expected_buckets)
    },
    "test_language": "English; original SMS corpus held-out split",
    "multilingual_training_by_language_and_label": {
        f"{language}_risk_{label}": int(count)
        for (language, label), count in multilingual.groupby(["language", "target"]).size().items()
    } if len(multilingual) else {},
    "test_samples": int(len(y_test)),
    "precision": round(float(precision_score(y_test, y_pred)), 4),
    "recall": round(float(recall_score(y_test, y_pred)), 4),
    "f1_score": round(float(f1_score(y_test, y_pred)), 4),
    "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
    "notification_threshold": 0.3,
    "notification_scoring": "word+character model, multilingual rules, explicit-safe-context cap",
    "notification_precision": round(float(precision_score(y_test, y_pred_notification)), 4),
    "notification_recall": round(float(recall_score(y_test, y_pred_notification)), 4),
    "notification_f1_score": round(float(f1_score(y_test, y_pred_notification)), 4),
}
(MODELS_DIR / "nlp_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
print("\nSaved model to models/nlp_model.joblib")
print("Saved vectorizer to models/nlp_vectorizer.joblib")
print("Saved evaluation metrics to models/nlp_metrics.json")
