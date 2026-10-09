def detect_anomalies(document_data: dict):
    anomalies = []
    if not document_data.get("name"):
        anomalies.append("MISSING_NAME")
    if not document_data.get("document_number"):
        anomalies.append("MISSING_DOCUMENT_NUMBER")
    if not document_data.get("expiry_date"):
        anomalies.append("MISSING_EXPIRY_DATE")
    return {"anomalies": anomalies, "count": len(anomalies)}
