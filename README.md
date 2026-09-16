# UPI Fraud Guard

An explainable, pre-transaction UPI fraud-warning prototype. It combines three
independent signals into one final verdict:

- **Message intelligence:** the included TF-IDF + Logistic Regression model scores scam-like SMS/WhatsApp language.
- **Link and QR payload analysis:** transparent checks for shortened links, raw IP hosts, non-HTTPS URLs, risky lure words, and UPI payment payloads.
- **Transaction signals:** amount, new-recipient, frequency and time-of-day indicators.

The browser demo includes a responsive payment-check workspace, explanation of every verdict, per-module scores, and an SQLite-backed local audit trail.

## Run the demo

```bash
pip install -r requirements.txt
python run_api.py
```

Then visit `http://127.0.0.1:8000`. Developer API documentation is available at `/api-docs`.

## Main API

`POST /check` accepts any combination of message, `url_or_qr`, amount,
recipient, `payments_last_hour`, and `is_new_recipient`. It returns a Safe,
Suspicious, or High Risk verdict with score, reasons and module scores. The
original `/check-message` route is retained for compatibility.

## Important prototype boundary

The NLP component is model-backed; the URL/QR and transaction modules use
explicit, explainable heuristics until labelled datasets are added and trained.
The system is a decision-support demo and should not automatically approve or
block a real payment.

## Setup (do this once)

Open this folder in VS Code, open a terminal (**Terminal -> New Terminal**), then run:

```
pip install -r requirements.txt
python setup.py
```

That installs everything needed and trains the model. You'll see some accuracy numbers print out -- that's it working correctly.

## Run it

```
python run_api.py
```

Then open **http://localhost:8000** in your browser -- this opens the actual demo app: a mock payment screen where you paste a message and watch the system check it before "paying", step by step.

Click one of the "Try: a scam example / a safe example" buttons to auto-fill a message, or paste your own, then click **Check before paying**.

The raw API testing page (for developers, not for demoing) is at http://localhost:8000/api-docs if you ever need it.

To stop the server, click into the terminal and press `Ctrl+C`.

## That's the whole thing
Two commands to set up, one command to run, every time after that. No need to move between folders -- always run these from the main `upi-fraud-system` folder.

## If something goes wrong
Copy the error text and share it -- it's usually a missing package or a Python version issue, both quick fixes.

## What's inside (for reference, not needed to run it)
- `nlp_module/` -- the scripts that clean data and train the message-risk model
- `models/` -- the trained model, created after you run `setup.py`
- `api/` -- the server code that `run_api.py` starts (also serves the frontend)
- `frontend/` -- the demo app (index.html, style.css, script.js)
- `data/` -- the training dataset

## Honest status (good to know before a demo)
- **All three detection modules are now model-backed AND trained on REAL data.** This is the big update: the transaction module now trains on the real PaySim dataset (6.36M real mobile-money transactions, Kaggle: `ealaxi/paysim1`), not synthetic data.
- **Message model**: TF-IDF + Logistic Regression, real SMS Spam Collection dataset (~5,572 messages). ROC-AUC 0.986.
- **New: real OpenPhish feed integrated.** Added 300 more real, currently-active phishing URLs (source: https://openphish.com/feed.txt, a free community-maintained phishing feed) on top of the original 997-URL academic dataset -- the URL model now trains on 2,426 real URLs total (up from 2,008).
  - **Important, genuinely worth telling your mentor**: adding this data initially *broke* the model in an interesting way. The 300 new phishing URLs (and the original 997) mostly use short root-domain links (e.g. `https://ledgerw.vercel.app/login`), while the academic legitimate-URL dataset is from ~2013 and mostly has long, deep-path URLs (e.g. `http://www.ceres.dti.ne.jp/~nekoi/senno/senfirst.html`). The model learned "short URL = phishing" as a shortcut, and started flagging `google.com` and `wikipedia.org` as high risk.
  - **The fix**: added `data/real_url_lists/modern_legit_roots.txt` -- 118 real, short, root-domain legitimate URLs (major banks, UPI apps, government sites, well-known tech companies) to give the model enough short *legitimate* examples too, correcting the imbalance. After retraining: ROC-AUC improved to **0.968** (up from 0.95), and `wikipedia.org`/`google.com` correctly score as Safe again while the new phishing URLs are correctly flagged as risky.
  - **New: real PhishTank data integrated.** Added 6,257 more real, human-verified, currently-online phishing URLs (source: https://phishtank.org, sampled from a 75,812-row export, prioritizing finance/bank/payment-brand impersonations directly relevant to a UPI-fraud project). The URL model now trains on 8,682 real URLs total.
  - **Two more real, worth-discussing problems were found and fixed while integrating this** -- on top of the short-URL bias caught earlier:
    1. **Extreme class imbalance**: real phishing sources now outnumbered real legitimate URLs roughly 7:1. Even `class_weight="balanced"` wasn't enough to stop the model over-flagging legitimate sites (it started scoring `paytm.com` as High Risk). Fixed with `RandomUnderSampler` (imbalanced-learn) applied to the *training* set only, capping the majority class at a 2:1 ratio -- the *test* set kept its full natural imbalance, so the printed metrics still reflect realistic real-world performance rather than an artificially easy balanced test.
    2. **A backwards HTTPS signal**: the older (~2013) legitimate-URL dataset predates widespread HTTPS adoption (0% of it uses HTTPS), while modern phishing hosted on free platforms like Vercel/Cloudflare Pages is ~81% HTTPS by default. The model learned "HTTPS = risky" -- exactly backwards, and a pure dataset-age artifact, not a real pattern. This matches a well-documented shift in the phishing-detection literature: HTTPS stopped being a useful phishing signal years ago once free, automatic certificates became universal. **Fixed by removing `has_https` as a model feature entirely** (see the note in `url_qr_module/url_features.py`) -- it's still checked and shown as a plain-language "reason" (a non-HTTPS link is still worth mentioning), it just no longer feeds the model's score.
  - **Net result**: on the specific real-world sanity checks that matter for a demo (real bank/UPI sites, real modern phishing links), the model now behaves correctly across the board. The held-out test-set ROC-AUC settled at **0.959** -- lower than an earlier intermediate version's 0.987, which is worth explaining honestly if asked: that higher number came from a model that was, underneath, using the backwards HTTPS shortcut and would have failed in exactly the way it initially failed on `paytm.com`. A slightly lower score from a model with a fixed, defensible feature set is more trustworthy than a higher score built on a confound.
  - **This whole sequence -- three real bugs found, diagnosed, and fixed while integrating real data -- is strong material for your report's "results and discussion" section and for a viva.** It shows genuine data science process (question your metrics, don't just chase a bigger number), not just plugging in files and reporting whatever number comes out.
- **Transaction model**: behavioural features (amount, new-recipient flag, recent payment frequency, time of day) + Random Forest, now trained on **real PaySim data** -- all 8,213 real fraud cases plus a 260,000-row sample of real non-fraud cases (kept at a realistic ~3% fraud rate, matching PaySim's actual imbalance). `2_train_model.py` compares three imbalance-handling strategies (baseline / `class_weight="balanced"` / SMOTE) on this real data.
  - **Honest, worth discussing in the viva**: ROC-AUC on real data is **0.84** (down from the earlier synthetic version's inflated ~0.99+) -- a much more credible, real-world number. Precision on the fraud class is low (~0.19) with recall ~0.62, meaning the model catches most real fraud but also raises a fair number of false alarms -- a realistic trade-off for imbalanced fraud detection, not a bug.
  - Interestingly, on real data `amount` and `is_night` turned out to be the dominant signals, while `is_new_recipient` and `payments_last_hour` had almost no predictive value -- the opposite of what the earlier synthetic dataset suggested. This is because PaySim's simulated transactions are nearly always between a sender/recipient pair for the first time, and rarely burst multiple payments in the same hour, so those two features don't vary much in this dataset. **Worth stating in your report as a genuine, defensible finding** -- real data revealed a limitation of features that looked useful on synthetic data.
  - `data/paysim.csv` (the raw 470MB file) is NOT included in this zip -- it's too large to ship. If you need to regenerate `transactions_dataset.csv` from scratch, place your downloaded PaySim CSV at `data/paysim.csv` and rerun `python setup.py` (or just `python transaction_module/1_generate_dataset.py`). The already-processed, much smaller `data/transactions_dataset.csv` (268,213 rows, ~5MB) IS included, so you don't need the raw file just to retrain the model.
- For explainability, each module keeps its original rule-based checks (HTTPS/shortener/lure-word detection, amount/frequency/recipient thresholds) running alongside the ML model -- the model sets the score, the rules generate the plain-language reasons. This is a lightweight stand-in for the SHAP-based explainability engine noted as a later phase in the project report.
- Security/privacy baseline: QR images are decoded in memory and never written to disk; CORS is restricted to localhost (not left open to `*`); request fields have length/range limits to reject oversized input before it reaches the model or database layer. Still open for a later phase: automatic audit-log retention limits (the SQLite history currently grows unbounded) and full SHAP-based explanations.
- **New: IEEE-CIS cross-dataset validation (an honest negative-ish result -- important for the report).** As requested for "cross-validating against a second real dataset," I tested the PaySim-trained transaction model against IEEE-CIS's real fraud data (Kaggle: `ieee-fraud-detection`, 590,540 real transactions, 3.5% fraud rate). See `transaction_module/evaluate_on_ieee.py` for the full script and its detailed docstring.
  - **Critical caveat, stated upfront**: IEEE-CIS is CARD/E-COMMERCE fraud data (a shopper's card transaction with a merchant), not peer-to-peer transfer fraud like PaySim or real UPI payments. There's no genuine "recipient" concept to map onto -- `is_new_recipient` and `payments_last_hour` had to be approximated from the card identifier (`card1`), not a true recipient. This is disclosed plainly rather than glossed over.
  - **Result 1 -- direct cross-domain transfer**: running the PaySim-trained model, completely unmodified, on IEEE-CIS data scored **ROC-AUC 0.48** -- essentially random guessing. The patterns learned from P2P transfer fraud (PaySim) do NOT transfer to card/e-commerce fraud (IEEE-CIS).
  - **Result 2 -- a fresh model trained on IEEE-CIS's own data**, using the same 4-feature schema and approach: **ROC-AUC 0.667** -- clearly better than random, but far below the 0.84 achieved on PaySim's own data. This is because IEEE-CIS's real fraud signal lives mostly in ~430 anonymized columns (device info, email domains, card metadata) that this project's narrow, UPI-specific 4-feature schema was never designed to use.
  - **Why this is still valuable to report, not a failure to hide**: it demonstrates real scientific honesty -- you tested whether your approach generalizes across domains, found that it correctly does NOT (because P2P transfer fraud and card/e-commerce fraud are genuinely different problems with different signals), and can explain *why* with evidence. This is a stronger answer to a mentor's "did you validate this properly?" than simply not testing it at all, or than a suspiciously perfect cross-domain score would have been.
  - This evaluation is NOT wired into the live API -- it's a standalone research script, run separately, producing `models/ieee_cross_validation_metrics.json` and a reference-only `models/ieee_transaction_model.joblib` that the app doesn't use. The raw IEEE-CIS CSV (~650MB) is not included in this zip; place `train_transaction.csv` from Kaggle at `data/ieee_train_transaction.csv` and run `python transaction_module/evaluate_on_ieee.py` to reproduce.
- **Real SHAP-based explainability.** Every `/check` response now includes a `shap_explanations` field with genuine per-prediction model attribution -- not the rule-based "reasons" text, but the actual mathematical contribution of each feature to THIS specific score. For the URL and transaction models (Random Forests), this uses `shap.TreeExplainer` directly. For the message model (a linear TF-IDF + Logistic Regression model), each word's exact contribution is computed directly as `coefficient x TF-IDF weight` -- the same underlying math SHAP's `LinearExplainer` uses for linear models. This is displayed in the frontend under "Model attribution (SHAP)" on the Risk analyser tab, showing which specific words/features pushed the score up (red) or down (green) for that exact input -- e.g. the word "urgent" might strongly increase risk while "pin" alone slightly decreases it, which a fixed rule-based system could never surface.
- **New: audit-log retention policy.** Completed checks are now automatically deleted from the local SQLite log after 90 days (`AUDIT_LOG_RETENTION_DAYS` in `api/main.py`) -- the database no longer grows unbounded. The sweep runs on server startup and probabilistically after new writes, so it doesn't add a query to every single request.
