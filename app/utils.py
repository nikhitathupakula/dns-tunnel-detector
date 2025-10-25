import os
import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "dns_model.pkl")

model = joblib.load(MODEL_PATH)

def predict(features):
    X = np.array(features).reshape(1, -1)
    result = model.predict(X)[0]
    return "Suspicious" if result == 1 else "Benign"
