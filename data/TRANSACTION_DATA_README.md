# Transaction data and PaySim file

The repository includes the processed model input at `data/transactions_dataset.csv`. It has 268,213 rows: 260,000 normal and 8,213 fraud-labelled rows. The original PaySim CSV is about 494 MB uncompressed and is intentionally excluded from Git.

Normal `python setup.py` runs reuse the processed table. To intentionally rebuild it from PaySim, obtain the original CSV separately, place it at `data/paysim.csv`, and set `UPI_FRAUD_GUARD_REBUILD_TRANSACTIONS=1` before running `python setup.py`. If neither file exists, the generator falls back to synthetic demo data.

PaySim is simulated mobile-money data, not actual bank transaction records. The model uses engineered amount, new-recipient, payments-per-hour and time-of-day features. It is not connected to a live UPI or bank transaction stream. Packaged metrics are benchmarks, not guarantees.
