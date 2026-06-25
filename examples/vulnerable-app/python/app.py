import requests
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    # Fetch a webpage using requests library
    response = requests.get("https://example.com")
    return response.text

if __name__ == "__main__":
    app.run()
