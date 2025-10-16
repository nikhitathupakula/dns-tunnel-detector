import os
import glob
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import xgboost as xgb

# -------------------
# Paths
# -------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")

# Collect files
heavy_files = glob.glob(os.path.join(DATA_DIR, "Attack_heavy_Benign", "Attacks", "*.pcap.csv"))
light_files = glob.glob(os.path.join(DATA_DIR, "Attack_light_Benign", "Attacks", "*.pcap.csv"))
benign_files = glob.glob(os.path.join(DATA_DIR, "Attack_heavy_Benign", "Benign", "*.pcap.csv"))
benign_files += glob.glob(os.path.join(DATA_DIR, "Attack_light_Benign", "Benign", "*.pcap.csv"))

print(f"✅ Found {len(benign_files)} benign files")
print(f"✅ Found {len(light_files)} light attack files")
print(f"✅ Found {len(heavy_files)} heavy attack files")

# -------------------
# Data loader
# -------------------
def load_and_clean(file, label):
    df = pd.read_csv(file)
    df["label"] = label
    # Drop string-heavy or unneeded columns if present
    drop_cols = [
        "timestamp", "rr_type", "subdomain", "reverse_dns", "distinct_ip",
        "unique_country", "unique_asn", "distinct_domains", "a_records"
    ]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")
    # Convert everything numeric
    df = df.apply(pd.to_numeric, errors="coerce")
    return df

# -------------------
# Load datasets
# -------------------
dfs = []
for f in benign_files:
    dfs.append(load_and_clean(f, 0))
for f in light_files + heavy_files:
    dfs.append(load_and_clean(f, 1))

data = pd.concat(dfs, ignore_index=True)

# Cleanup
data = data.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e9, 1e9)
X = data.drop(columns=["label"])
y = data["label"]

# -------------------
# Train/test split
# -------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# -------------------
# RandomForest
# -------------------
rf = RandomForestClassifier(
    n_estimators=300, random_state=42, class_weight="balanced"
)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)

print("\n📊 RandomForest Report:\n")
print(classification_report(y_test, rf_pred, target_names=["Benign", "Attack"]))

# Feature importances
rf_importances = pd.DataFrame({
    "Feature": X.columns,
    "Importance": rf.feature_importances_
}).sort_values(by="Importance", ascending=False)
print("\n🔎 RandomForest Feature Importances:\n")
print(rf_importances.to_string(index=False))

# -------------------
# XGBoost
# -------------------
scale_pos_weight = len(y_train[y_train == 0]) / len(y_train[y_train == 1])
print(f"\nℹ️ scale_pos_weight = {scale_pos_weight:.2f}")

xgb_clf = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric="logloss",
    scale_pos_weight=scale_pos_weight,
)
xgb_clf.fit(X_train, y_train)
xgb_pred = xgb_clf.predict(X_test)

print("\n📊 XGBoost Report:\n")
print(classification_report(y_test, xgb_pred, target_names=["Benign", "Attack"]))

# Feature importances
xgb_importances = pd.DataFrame({
    "Feature": X.columns,
    "Importance": xgb_clf.feature_importances_
}).sort_values(by="Importance", ascending=False)
print("\n🔎 XGBoost Feature Importances:\n")
print(xgb_importances.to_string(index=False))

# -------------------
# Save models
# -------------------
os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(rf, os.path.join(MODEL_DIR, "dns_rf_model.pkl"))
joblib.dump(xgb_clf, os.path.join(MODEL_DIR, "dns_xgb_model.pkl"))
print(f"\n✅ Models saved in {MODEL_DIR}")