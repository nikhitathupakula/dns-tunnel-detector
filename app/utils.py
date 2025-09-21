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