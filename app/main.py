# app/main.py
<<<<<<< HEAD
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
=======
from app.utils import log_prediction
from fastapi import FastAPI
from pydantic import BaseModel
from app.utils import predict

app = FastAPI(title="DNS Tunneling Detection API")

# request schema
class DNSRequest(BaseModel):
    query_length: int
    entropy: float
    nxdomain_ratio: float
    char_digit_ratio: float

@app.post("/predict")
def predict_dns(data: DNSRequest):
    features = [data.query_length, data.entropy, data.nxdomain_ratio, data.char_digit_ratio]
    prediction = predict(features)
    log_prediction(features, prediction)
    return {"prediction": prediction}
>>>>>>> upstream/main

@app.get("/healthz")
def health_check():
    return {"status": "ok"}
<<<<<<< HEAD
=======
#commented

>>>>>>> upstream/main
