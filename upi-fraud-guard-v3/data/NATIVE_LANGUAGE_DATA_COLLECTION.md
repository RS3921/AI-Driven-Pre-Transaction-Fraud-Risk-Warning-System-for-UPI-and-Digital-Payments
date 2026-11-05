# Native-language evaluation data: team workflow

## Why this file is a template

The repository does not contain consented, native-speaker-reviewed examples supplied by real message recipients. Do not present synthetic, translated, or invented messages as consented field data. Use this template only after obtaining informed permission for each example and having a fluent native speaker review the language and label.

## Collection and review rules

1. Explain what will be collected, why it is being evaluated, who can access it, how long it will be retained, and that participation is voluntary. Obtain explicit permission to use each example for model evaluation. Do not collect messages from a device or chat without the sender/recipient's permission.
2. Remove names, phone numbers, email addresses, UPI IDs, bank/account details, URLs, OTPs, and other identifying or secret information before adding a row. Preserve only the wording needed to assess scam cues. Never include the participant's identity.
3. Have a fluent native speaker for the specified language/script confirm that the message sounds natural and that the safe/risky label fits its meaning. Use a different reviewer from the person who assigned the initial label where possible.
4. Use `source_group` as an anonymous random group code, not a phone number, name, or account ID. If multiple examples came from the same source/campaign/conversation, give them the same group code.
5. Keep rows in `data/native_language_reviewed.csv` on a controlled local machine. The evaluator writes aggregate counts only; it does not put message text, IDs, or source-group codes into the metrics JSON.
6. Aim for at least 100 reviewed safe and 100 reviewed risky examples per language, drawn from at least 20 independent source groups in each class, before interpreting rates. The evaluator reports both message and source-group support. Report smaller support explicitly. One missed scam or false alert matters; aggregate accuracy alone is not sufficient.

## CSV columns

- `record_id`: random row identifier with no personal information.
- `language`: English, Hindi, Marathi, Hinglish, or another language name.
- `message`: redacted message text that consent covers for evaluation.
- `target`: `0` for safe/legitimate, `1` for suspicious/risky, based on reviewed meaning.
- `consent_for_evaluation`: `yes` only when the contributor explicitly agreed to this use.
- `review_status`: `approved` only after native-language and label review; otherwise leave `pending`.
- `native_speaker_reviewed`: `yes` only when a qualified fluent/native speaker reviewed it.
- `source_group`: anonymous random grouping value used to avoid counting closely related examples as independent evidence.

Start by copying the header from `native_language_review_template.csv` into `native_language_reviewed.csv`. Once reviewed rows are ready, run `python nlp_module/7_evaluate_native_reviewed.py`. The script excludes unconsented, pending, non-native-reviewed, malformed, and exact training-text duplicates, then reports risky recall (missed scams), safe false-positive rate, precision, and support separately for each language. It does not train the model or modify any model file.

This local CSV is sensitive even after redaction. Keep it out of public source control and remove it when the approved evaluation period ends. Retain the aggregate metrics only if they cannot identify a participant.
