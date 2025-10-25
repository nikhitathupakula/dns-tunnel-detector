import pandas as pd
import os
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
import joblib

# -----------------------
# Paths - update to your new folder
# -----------------------
data_dir = "data"
train_csv = os.path.join(data_dir, "pcap_train_full.csv")
#val_csv   = os.path.join(data_dir, "pcap_val.csv")
test_csv  = os.path.join(data_dir, "pcap_test_full.csv")

models_dir = "scripts/models"
os.makedirs(models_dir, exist_ok=True)

# -----------------------
# Load datasets
# -----------------------
train_df = pd.read_csv(train_csv)
test_df  = pd.read_csv(test_csv)


# -----------------------
# Features used from PCAP extraction
# -----------------------
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

# Fill NaN caused by missing AN/AR records
train_df[feature_cols] = train_df[feature_cols].fillna(0)
test_df[feature_cols] = test_df[feature_cols].fillna(0)

X_train = train_df[feature_cols].values
y_train = train_df["label"].values

X_test = test_df[feature_cols].values
y_test = test_df["label"].values

# -----------------------
# Scale features
# -----------------------
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
joblib.dump(scaler, os.path.join(models_dir, "scaler_pcap.pkl"))
print(f"💾 Scaler saved → {models_dir}/scaler_pcap.pkl")

# -----------------------
# Balance classes
# -----------------------
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
print("Balanced class distribution:\n", pd.Series(y_train_bal).value_counts())

"""# -----------------------
# Train Random Forest
# -----------------------
print("\n🌲 Training Random Forest...")
rf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
rf.fit(X_train_bal, y_train_bal)
y_pred_rf = rf.predict(X_test)

print("\n=== Random Forest Report ===")
print(classification_report(y_test, y_pred_rf))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))

joblib.dump(rf, os.path.join(models_dir, "rf_pcap.pkl"))
print(f"💾 Saved RF model → {models_dir}/rf_pcap.pkl")"""

# -----------------------
# Train Improved XGBoost (compatible syntax)
# -----------------------
print("\n🔥 Training Improved XGBoost...")

xgb = XGBClassifier(
    n_estimators=500,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    gamma=1,
    reg_alpha=0.1,
    reg_lambda=1,
    scale_pos_weight=1,
    eval_metric="logloss",
    use_label_encoder=False,
)

# Convert evaluation set format
eval_set = [(X_test, y_test)]

xgb.fit(
    X_train_bal,
    y_train_bal,
    eval_set=eval_set,
    verbose=False
)

y_pred_xgb = xgb.predict(X_test)

print("\n=== Improved XGBoost Report ===")
print(classification_report(y_test, y_pred_xgb))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_xgb))

joblib.dump(xgb, os.path.join(models_dir, "xgb_pcap.pkl"))
print(f"💾 Improved XGB Saved → {models_dir}/xgb_pcap.pkl")
