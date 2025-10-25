<<<<<<< HEAD
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
=======
from datetime import datetime
import random  # only if you’re using dummy predictions for now

logs = []

# Dummy prediction function for now
def predict(features):
    result = random.choice(["Benign", "Suspicious"])
    log_prediction(features, result)
    return result

# Logging function
def log_prediction(features, prediction):
    logs.append({
        "time": datetime.now().isoformat(),
        "features": features,
        "prediction": prediction
    })
#commented
>>>>>>> upstream/main
