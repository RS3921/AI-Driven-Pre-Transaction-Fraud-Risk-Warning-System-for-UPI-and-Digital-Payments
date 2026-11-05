# Transaction data and PaySim file

The project ZIP includes the original PaySim CSV at `data/paysim.csv` and the processed model input at `data/transactions_dataset.csv`. The raw CSV is about 494 MB uncompressed. The processed table has 268,213 rows: 260,000 normal and 8,213 fraud-labelled rows. The API model is trained from this processed table.

Normal `python setup.py` runs reuse the included processed table and do not re-import the large raw CSV. The setup message will identify both files and continue training. You do not need to copy the CSV into the project again after extraction.

To intentionally rebuild `transactions_dataset.csv` from the included raw CSV, set `UPI_FRAUD_GUARD_REBUILD_TRANSACTIONS=1` before running `python setup.py`. If neither file exists, the generator falls back to synthetic demo data.

PaySim is simulated mobile-money data, not actual bank transaction records. The model uses engineered amount, new-recipient, payments-per-hour and time-of-day features. It is not connected to a live UPI or bank transaction stream. Packaged metrics are benchmarks, not guarantees.
