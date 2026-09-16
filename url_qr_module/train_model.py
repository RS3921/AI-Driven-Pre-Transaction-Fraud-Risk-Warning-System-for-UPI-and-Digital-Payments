"""
Train the URL/QR risk classifier -- this is the "URL ML model" item that
was previously "Not started" in the project status table.

WHAT THIS SCRIPT DOES (in plain terms):

1. Loads a REAL, labeled dataset -- 1,016 real legitimate URLs and 997
   real phishing URLs, bundled in data/real_url_lists/ (source:
   chamanthmvs/Phishing-Website-Detection on GitHub, an openly reused
   academic phishing-URL dataset -- cite this source in the report the
   same way you'd cite a Kaggle dataset).

2. Runs every URL through extract_features() (url_features.py) to turn
   it into a row of numbers -- lexical signals like URL length, use of
   HTTPS, IP addresses instead of domains, shortener services, etc.

3. Trains a Random Forest classifier -- a good fit for this kind of
   small tabular numeric feature set, and its feature_importances_
   double as a plain explanation of what the model is picking up on.

4. Evaluates with precision/recall/F1/ROC-AUC and saves both the model
   and a metrics.json (mirrors nlp_module/2_train_model.py's pattern),
   so /model-metrics can serve URL-model quality alongside the NLP one.

IMPORTANT DESIGN CHOICE -- why analyzer.py still keeps the rule-based
checks after this: the ML score becomes the module's actual risk score,
but the existing rule-based checks (analyze for HTTPS, shorteners, lure
words, etc.) are kept and used purely to generate the human-readable
"reasons" shown to the user. This gives the best of both: a model-backed
score, with transparent, plain-language reasons -- without needing a
full SHAP integration (which the README notes as a planned later phase).

Run it with:  python train_model.py
"""

import sys
from pathlib import Path

import joblib
import json
import pandas as pd
from imblearn.under_sampling import RandomUnderSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "url_qr_module"))
from url_features import extract_features, FEATURE_NAMES  # noqa: E402

DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)
REAL_URLS_DIR = DATA_DIR / "real_url_lists"


def load_dataset() -> pd.DataFrame:
    """
    Loads every real URL file present in data/real_url_lists/:
      - legitimate_urls.txt        (1,016 real safe URLs, academic dataset, mostly older/deep-path URLs)
      - modern_legit_roots.txt     (120+ short, modern, real root-domain URLs
                                     added after discovering that the academic
                                     legit dataset skews toward long, deep-path
                                     URLs while phishing URLs -- old and new --
                                     skew toward short root-domain URLs. Without
                                     this, the model learned "short URL = risky"
                                     as a shortcut and flagged sites like
                                     google.com / wikipedia.org as high risk.
                                     This file corrects that class-conditional
                                     imbalance with real short legitimate URLs.)
      - 1000-phishing.txt          (997 real phishing URLs, academic dataset)
      - openphish_feed.txt         (300 live phishing URLs from
                                     https://openphish.com/feed.txt)
      - phishtank_feed.txt         (7,256 real, human-VERIFIED phishing URLs
                                     sampled from PhishTank's full verified+
                                     online feed of 75,812 entries -- sampling
                                     prioritizes finance/bank/payment-brand
                                     impersonations (Amazon, PayPal, banks,
                                     tax authorities, etc.), directly relevant
                                     to a UPI/payment-fraud project, plus a
                                     random sample of other categories for
                                     general pattern diversity. Source:
                                     https://phishtank.org, a free community-
                                     verified phishing database.)
    Any of these files can be added or swapped later (e.g. a PhishTank
    export, or manually-collected UPI-specific phishing links) just by
    dropping a same-shaped .txt file into that folder and adding its
    name to PHISHING_FILES / LEGIT_FILES below.
    """
    legit_files = ["legitimate_urls.txt", "modern_legit_roots.txt"]
    legit_urls: list[str] = []
    for filename in legit_files:
        path = REAL_URLS_DIR / filename
        if path.exists():
            urls = [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]
            print(f"  + {filename}: {len(urls)} URLs")
            legit_urls.extend(urls)

    phishing_files = ["1000-phishing.txt", "openphish_feed.txt", "phishtank_feed.txt"]
    phishing_urls: list[str] = []
    for filename in phishing_files:
        path = REAL_URLS_DIR / filename
        if path.exists():
            urls = [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]
            print(f"  + {filename}: {len(urls)} URLs")
            phishing_urls.extend(urls)

    rows = [{"url": u, "target": 0} for u in legit_urls] + [{"url": u, "target": 1} for u in phishing_urls]
    return pd.DataFrame(rows).drop_duplicates(subset="url")


print("Loading real URL data sources:")


df = load_dataset()
print(f"Loaded {len(df)} real URLs")
print(df["target"].value_counts().rename({0: "legit", 1: "phishing"}))

feature_rows = df["url"].apply(extract_features).apply(pd.Series)
X = feature_rows[FEATURE_NAMES]
y = df["target"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"\nTraining on {len(X_train)} URLs, testing on {len(X_test)} URLs\n")

# The real-world phishing sources (PhishTank + OpenPhish) vastly outnumber
# the real legitimate-URL examples (thousands vs ~1,100) -- far more
# skewed than class_weight="balanced" alone can correct for; it was
# tested and still let the model drift toward over-flagging legitimate
# sites like paytm.com as risky. RandomUnderSampler fixes this properly
# by capping the majority (phishing) class in the TRAINING set only, at
# a 2:1 ratio -- the TEST set below keeps the full, natural, imbalanced
# distribution, so the printed metrics still reflect realistic
# real-world performance rather than an artificially balanced test.
undersampler = RandomUnderSampler(sampling_strategy=0.5, random_state=42)
X_train, y_train = undersampler.fit_resample(X_train, y_train)
print(f"After undersampling majority class for training: {len(X_train)} rows "
      f"({y_train.value_counts().to_dict()})\n")

model = RandomForestClassifier(n_estimators=200, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

print("=== Classification report ===")
print(classification_report(y_test, y_pred, target_names=["legit (safe)", "phishing (risky)"]))
cm = confusion_matrix(y_test, y_pred)
print("=== Confusion matrix ===")
print(f"                 predicted legit   predicted phishing")
print(f"actual legit          {cm[0][0]:>5}              {cm[0][1]:>5}")
print(f"actual phishing       {cm[1][0]:>5}              {cm[1][1]:>5}")
print(f"\nROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

importances = pd.Series(model.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)
print("\n=== Feature importance ===")
print(importances.to_string())

joblib.dump(model, MODELS_DIR / "url_model.joblib")
metrics = {
    "model": "Lexical features + Random Forest",
    "test_samples": int(len(y_test)),
    "precision": round(float(precision_score(y_test, y_pred)), 4),
    "recall": round(float(recall_score(y_test, y_pred)), 4),
    "f1_score": round(float(f1_score(y_test, y_pred)), 4),
    "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
}
(MODELS_DIR / "url_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
print("\nSaved model to models/url_model.joblib")
print("Saved evaluation metrics to models/url_metrics.json")
