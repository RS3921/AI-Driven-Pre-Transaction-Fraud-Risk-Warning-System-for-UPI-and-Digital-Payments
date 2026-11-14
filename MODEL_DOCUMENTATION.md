# MACHINE LEARNING MODEL DOCUMENTATION

---

## 1. Subsystem Architecture

UPI Fraud Guard employs a **Tri-Module ML Fusion Engine**:

1. **Module 1: Multilingual Text Risk Classifier**
   * **Algorithm**: Word + Character TF-IDF Vectorization with Logistic Regression / XGBoost Classifier.
   * **Language Loss Allocation**: Equal weighting across English (25%), Hindi (25%), Marathi (25%), and Hinglish (25%).
   * **Performance**: Test Precision: `96.5%`, Recall: `92.6%`, F1-Score: `94.5%`, ROC-AUC: `0.996`.

2. **Module 2: Lexical URL & Heuristic Rule Engine**
   * **Algorithm**: Lexical Feature Extractor + Random Forest Classifier.
   * **Performance**: Test Precision: `98.3%`, Recall: `87.9%`, F1-Score: `92.8%`, ROC-AUC: `0.958`.

3. **Module 3: Behavioral Transaction Scorer & Velocity Engine**
   * **Algorithm**: Behavioral Feature Extractor + Random Forest Classifier (`class_weight='balanced'`).
   * **Performance**: ROC-AUC: `0.840`.

---

## 2. Explainable AI (XAI) with SHAP

* **Linear Model Attribution**: Computes exact feature contributions ($w_i \cdot x_i$) for words in text messages.
* **Feature Direction**: Labels features as `increased_risk` or `decreased_risk` to provide transparent reasons for every verdict.

---

## 3. Data Drift Monitoring

* **Statistical Drift Analysis**: Evaluates recent prediction risk score distributions against the baseline mean (`0.15`).
* **Alert Trigger**: Triggers a data drift warning if mean risk score deviates by more than `0.20`.
