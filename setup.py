"""
Run this ONCE to set everything up: cleans the data and trains all three models.

Just run:   python setup.py
"""

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
NLP_DIR = BASE_DIR / "nlp_module"
URL_DIR = BASE_DIR / "url_qr_module"
TXN_DIR = BASE_DIR / "transaction_module"

steps = [
    ("Cleaning the message dataset", NLP_DIR / "1_prepare_data.py", NLP_DIR),
    ("Training the message model", NLP_DIR / "2_train_model.py", NLP_DIR),
    ("Testing the message model on sample messages", NLP_DIR / "3_predict.py", NLP_DIR),
    ("Training the URL/QR model on real phishing-URL data", URL_DIR / "train_model.py", URL_DIR),
    ("Generating the transaction dataset", TXN_DIR / "1_generate_dataset.py", TXN_DIR),
    ("Training the transaction model", TXN_DIR / "2_train_model.py", TXN_DIR),
]

for title, script, cwd in steps:
    print(f"\n{'=' * 60}\n{title}...\n{'=' * 60}")
    result = subprocess.run([sys.executable, str(script)], cwd=cwd)
    if result.returncode != 0:
        print(f"\nSomething went wrong during: {title}")
        print("Copy the error above and share it to get help fixing it.")
        sys.exit(1)

print("\nAll done! All three models are trained and saved in the models/ folder.")
print("Next: run   python run_api.py   to start the server.")
