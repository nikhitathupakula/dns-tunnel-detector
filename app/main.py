# app/main.py
from fastapi import FastAPI
from pydantic import BaseModel
try:
    from app.utils import predict, log_prediction
except Exception as e:
    print(f"❌ Failed to import utils: {e}")
    predict = lambda x: "Error"
    log_prediction = lambda *a, **kw: None


app = FastAPI(title="DNS Tunneling Detection API")

class DNSRequest(BaseModel):
    query_length: int
    entropy: float
    nxdomain_ratio: float
    char_digit_ratio: float

@app.post("/predict")
def predict_dns(data: DNSRequest):
    features = [
        data.query_length,
        data.entropy,
        data.nxdomain_ratio,
        data.char_digit_ratio,
    ]
    prediction = predict(features)
    log_prediction(features, prediction)
    return {"prediction": prediction}

@app.get("/healthz")
def health_check():
    return {"status": "ok"}


from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for testing; restrict to your frontend URL in production
    allow_methods=["*"],
    allow_headers=["*"],
)

