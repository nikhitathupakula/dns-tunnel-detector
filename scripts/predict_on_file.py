# scripts/predict_pcap_features.py
import pandas as pd
import os
import joblib
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

# -----------------------
# Paths
# -----------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
models_dir = os.path.join(BASE_DIR, "models")

SCALER_PATH = os.path.join(models_dir, "scaler_pcap.pkl")
RF_MODEL_PATH = os.path.join(models_dir, "rf_pcap.pkl")
XGB_MODEL_PATH = os.path.join(models_dir, "xgb_pcap.pkl")

TEST_CSV = os.path.join(BASE_DIR, "..", "data", "pcap_test_full.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "pcap_test_predictions.csv")
os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

# -----------------------
# Load scaler and models
# -----------------------
scaler = joblib.load(SCALER_PATH)
print(f"📦 Loaded scaler from {SCALER_PATH}")

rf_model = joblib.load(RF_MODEL_PATH)
print(f"📦 Loaded Random Forest model from {RF_MODEL_PATH}")

try:
    xgb_model = joblib.load(XGB_MODEL_PATH)
    print(f"📦 Loaded XGBoost model from {XGB_MODEL_PATH}")
    use_xgb = True
except FileNotFoundError:
    print("⚠️ XGBoost model not found. Will only use Random Forest.")
    use_xgb = False

# -----------------------
# Load test data
# -----------------------
df_test = pd.read_csv(TEST_CSV)

# Features used in training
feature_cols = [
    'qd_qname_len',
    'qd_qname_shannon',
    'qdcount',
    'ancount',
    'arcount',
    'nscount',
    'qd_qtype',
    'an_rrname_len',
    'an_rrname_shannon',
    'an_type',
    'an_ttl',
    'an_rdata_len',
    'an_rdata_shannon',
    'ar_rrname_len',
    'ar_rrname_shanonn',
    'ar_type',
    'ar_rdata_len',
    'ar_rdata_shannon'
]

df_test[feature_cols] = df_test[feature_cols].fillna(0)
X_test = scaler.transform(df_test[feature_cols])

# -----------------------
# Predict
# -----------------------
df_test['pred_rf'] = rf_model.predict(X_test)
print("\n=== Random Forest Classification Report ===")
if 'label' in df_test.columns:
    print(classification_report(df_test['label'], df_test['pred_rf']))
    cm = confusion_matrix(df_test['label'], df_test['pred_rf'])
    disp = ConfusionMatrixDisplay(confusion_matrix=cm)
    disp.plot(cmap='Blues')
    plt.show()

if use_xgb:
    df_test['pred_xgb'] = xgb_model.predict(X_test)
    print("\n=== XGBoost Classification Report ===")
    if 'label' in df_test.columns:
        print(classification_report(df_test['label'], df_test['pred_xgb']))
        cm = confusion_matrix(df_test['label'], df_test['pred_xgb'])
        disp = ConfusionMatrixDisplay(confusion_matrix=cm)
        disp.plot(cmap='Greens')
        plt.show()

# -----------------------
# Save predictions
# -----------------------
df_test.to_csv(OUTPUT_CSV, index=False)
print(f"\n💾 Predictions saved to: {OUTPUT_CSV}")
