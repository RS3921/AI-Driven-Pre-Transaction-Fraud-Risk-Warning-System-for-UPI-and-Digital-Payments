# Multilingual message-training data notes

## Source and attribution

The additional English, Hindi, and Hinglish examples are a filtered and redacted subset of **ScamShield: Multilingual Smishing & Social Engineering Corpus**, published at <https://huggingface.co/datasets/sidzzz07/scamshield-dataset>. The dataset card declares an MIT license and describes a mixture of crowdsourced and machine-generated, expert-annotated material. The source snapshot used for this project was revision `059dee884476a45e380808e68d09e74baff67291`.

The bundled ScamShield CSV files are derived from the source's `train` and `test` splits. Source rows marked `UCI_SMS_Spam` are excluded from the added training subset to reduce overlap with the project's existing SMS collection. All eligible rows from the source training split are included after exact-text deduplication against the existing and curated project data. Email addresses, URLs, and phone-like number strings are replaced with generic placeholders. `source_dataset` and `split_group` are retained for traceability.

An additional **127 Roman-script Marathi-English (Marathlish)** examples come from [Indian Scam SMS (synthetic, audited)](https://huggingface.co/datasets/Ridham115/indian-scam-sms-synthetic-audited), which declares CC BY 4.0. It contributes 62 safe and 65 risky rows after exact-text deduplication. The examples are synthetic, and 108 of the 127 Marathi rows are marked unreviewed by the dataset itself; they have not been reviewed by native Marathi speakers. They are included in training only, not represented as an independent test set. The accompanying `marathi_synthetic_supplement.csv` preserves row IDs, labels, audit status, and source attribution.

## Training data included

| Language group | Safe examples | Risky examples | Total |
| --- | ---: | ---: | ---: |
| English | 33,786 | 22,251 | 56,037 |
| Hindi | 4,725 | 501 | 5,226 |
| Hinglish | 1,531 | 1,164 | 2,695 |
| **External corpus total** | **40,042** | **23,916** | **63,958** |

Marathi/Marathlish has 63 existing curated examples and 127 synthetic Marathlish examples, plus **3,519 machine-translated Devanagari Marathi training examples** from a public translated SMS corpus. The translated set has 3,201 safe and 318 risky messages. Total Marathi-group training rows are now **3,709** (3,294 safe, 415 risky). The translated corpus is partitioned by its original English SMS: 938 unique source messages are held out (851 safe, 87 risky) and never included in training. The Marathi translation source is not native-speaker-written or reviewed and covers general SMS spam, not UPI-specific conversations.

The translated source dataset's Hugging Face card declares `GPL` (without specifying a version); it says the Marathi column was produced with M2M100_418M, while the underlying English SMS collection is separately identified as CC BY 4.0. The project includes only the filtered Marathi-English paired rows needed for provenance and leakage-safe splitting. Review upstream data and model-weight licensing before public or commercial release; this note does not determine downstream legal obligations.

The classifier assigns 25% of its total sample-weighted training loss to each group: English, Hindi, Marathi/Marathlish, and Hinglish. This makes language influence equal even though the datasets differ greatly in size. The model retains each group's natural safe/risky proportions; it does not artificially make half of every language's examples risky. That avoids teaching an inflated scam rate. Equal optimization weight does not mean equal evidence quality or equal coverage.

The external test CSV is built from the source's separate test split, excludes exact overlaps with the original/curated/training examples, and is never loaded by the training script. It has 7,636 examples after filtering: English safe 4,301 and risky 2,768; Hindi safe 449 and risky 11; Hinglish safe 12 and risky 95. Hindi risky and Hinglish safe counts are too small for dependable language-level performance estimates.

## Results and limitations

The project also includes a **60-example balanced regression smoke set**: English, Hindi, Marathi, Hinglish, and Marathlish each have 6 safe and 6 risky hand-authored examples. Run it with `python nlp_module/4_evaluate_multilingual.py`. This checks known examples after rule/model changes, but it is too small and too curated to estimate real-world accuracy. Run `python nlp_module/5_evaluate_external_holdout.py` for the separate public English/Hindi/Hinglish holdout. An independent, native-speaker-reviewed Marathi test set is still needed.

At the current notification threshold of 0.30, the separate external test evaluation reports English risky recall 97.6% and safe false-alert rate 4.72% (2,768 risky and 4,301 safe examples). Hindi recall is 72.7% (8/11 risky caught) and safe false-alert rate 0.22% (1/449 safe alerted). Hinglish recall is 100% (95/95 risky caught) and safe false-alert rate 25.0% (3/12 safe alerted). Treat the Hindi/Hinglish figures as unstable because the test support is small and the source labels/data may be noisy. These are benchmark results, not guarantees for Telegram, new scam campaigns, or real users.

On the 938-row source-grouped **machine-translated Marathi** holdout, the updated model caught 77/87 risky messages (88.5% recall) and alerted on 6/851 safe messages (0.7% false-alert rate). Before adding the translated training rows, the same evaluation caught 43/87 (49.4%) and alerted on 23/851 (2.7%). This is an apples-to-apples translation-transfer diagnostic with support from one translated SMS corpus; it is not a native Marathi or UPI field benchmark. It does not mean the Marathi problem is solved.

- This is one shared word-and-character classifier, not a separate model per language.
- The large ScamShield public source does not include Marathi. The translated SMS supplement increases Marathi script coverage, but its text is machine-translated from English and is not native-speaker-reviewed. Marathi therefore remains less validated for natural UPI messages than English or Hindi. The small hand-written smoke set and translated transfer holdout are not native-field accuracy benchmarks. A larger, consented, native-speaker-labelled Marathi dataset is still needed.
- English/Hindi/Hinglish source examples cover broad smishing and social engineering, not only UPI fraud. The source includes synthetic data and may contain labeling errors.
- Marathi and other regional languages are not covered by the external benchmark. Do not describe every language as equally validated; equal training influence is not equal dataset coverage.
- A model score is a warning signal, not proof that a message is fraudulent or safe. Review both false alerts and missed scams on representative, consented samples before real-world deployment.
- Do not use private Telegram messages for training or evaluation without informed consent and appropriate privacy handling.
