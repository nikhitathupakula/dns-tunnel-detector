# app/utils.py
import joblib
import os
import numpy as np
from datetime import datetime

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "model", "dns_rf_model.pkl")

# Load model once
model = joblib.load(MODEL_PATH)

# Simple in-memory log
logs = []

def predict(features: list) -> str:
    X = np.array(features).reshape(1, -1)
    pred = model.predict(X)[0]
    return "Suspicious" if pred == 1 else "Benign"

def log_prediction(features, prediction):
    logs.append({
        "time": datetime.now().isoformat(),
        "features": features,
        "prediction": prediction
    })
