import requests
from requests.utils import extract_zipped_paths
from flask import Flask, session

app = Flask(__name__)
app.secret_key = "super-secret"

@app.route("/")
def home():
    # Trigger flask CVE-2026-27205 (session access)
    session.get("user")
    
    # Trigger requests CVE-2026-25645 (Insecure temp file reuse)
    extract_zipped_paths("archive.zip")
    
    return "Hello"

if __name__ == "__main__":
    app.run()
