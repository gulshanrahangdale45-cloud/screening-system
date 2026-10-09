import re
def extract_document_text(path):
    # Test stub: reads a "NAME:" line from the file bytes instead of running Tesseract
    data = open(path, "rb").read().decode("latin-1")
    m = re.search(r"NAME:([A-Z ]+)", data)
    return {"name": m.group(1).strip() if m else None, "date_of_birth": None,
            "document_number": None, "expiry_date": None, "raw_text": "", "error": None}
