# app/main.py
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

@app.get("/healthz")
def health_check():
    return {"status": "ok"}


