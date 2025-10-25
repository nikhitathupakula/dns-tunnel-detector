# app/main.py
from fastapi import FastAPI
import joblib, os
import pandas as pd

app = FastAPI(title="DNS Tunneling Detection API")

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "dns_rf_model.pkl")

# Load trained model
clf = joblib.load(MODEL_PATH)

@app.post("/predict")
def predict(features: dict):
    # Convert dict to dataframe with one row
    X = pd.DataFrame([features])
    pred = clf.predict(X)[0]
    return {"prediction": int(pred)}

@app.get("/healthz")
def health_check():
    return {"status": "ok"}
