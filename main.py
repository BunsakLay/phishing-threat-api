import random
from datetime import datetime, timezone
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from extractor import extract_features, FEATURE_NAMES
from geo_intel import get_network_intelligence

app = FastAPI(
    title="Cloud Phishing URL & Threat Intelligence API",
    description="Supervised ML Phishing Classifier with Live DNS & GeoIP Enrichment",
    version="1.0.0"
)

# Load the trained supervised ML model at startup
model = joblib.load("phishing_model.pkl")


class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=4, example="http://secure-paypal-verify-login.xyz/update")


@app.get("/")
def health_check():
    return {
        "service": "Cloud Phishing URL & Threat Intelligence API",
        "status": "ONLINE",
        "ml_parameters": len(FEATURE_NAMES),
        "network_parameters": 5
    }


@app.post("/scan_url")
def scan_url(payload: URLScanRequest):
    target_url = payload.url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # 1. Extract the 24 supervised ML parameters
    feature_values = extract_features(target_url)
    features_df = pd.DataFrame([feature_values], columns=FEATURE_NAMES)

    # 2. Run supervised ML inference
    prediction = int(model.predict(features_df)[0])
    probabilities = model.predict_proba(features_df)[0]
    confidence = float(probabilities[prediction]) * 100

    # 3. Run live DNS IP & Geolocation enrichment (5 parameters)
    network_intel = get_network_intelligence(target_url)

    # 4. Construct SIEM Threat Intelligence Alert
    is_malicious = prediction == 1
    verdict = "Malicious" if is_malicious else "Non-Malicious"

    if is_malicious and confidence >= 80.0:
        severity = "HIGH"
        action = "BLOCK_AT_WAF"
    elif is_malicious:
        severity = "MEDIUM"
        action = "QUARANTINE_AND_INSPECT"
    else:
        severity = "LOW"
        action = "ALLOW"

    threat_id = f"TRT-{random.randint(1000, 9999)}"
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "threat_id": threat_id,
        "timestamp_utc": timestamp_utc,
        "submitted_url": target_url,
        "prediction_code": prediction,
        "verdict": verdict,
        "confidence_score": f"{confidence:.2f}%",
        "risk_severity": severity,
        "network_intelligence": network_intel,
        "recommended_action": action
    }