#!/usr/bin/env python
# coding: utf-8

# In[2]:


from flask import Flask, request, jsonify
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import sys


app = Flask(__name__)

# Load your trained model
try:
    model = joblib.load("URLphishing.joblib")
except Exception as e:
    error_msg = f"""
    Failed to load model: {str(e)}
    
    This is likely due to a scikit-learn version mismatch.
    Please try one of these solutions:
    
    1. Update scikit-learn:
       pip install --upgrade scikit-learn
    
    2. Or install a specific version (try one of these):
       pip install scikit-learn==1.0.2
       pip install scikit-learn==0.24.2
    
    3. If you have access to the training code, re-save the model
       with your current scikit-learn version.
    """
    print(error_msg, file=sys.stderr)
    raise RuntimeError("Model loading failed - see error message above")

# Feature extraction logic
def abnormal_url(url):
    try:
        hostname = urlparse(url).hostname
        return 1 if hostname and re.search(re.escape(hostname), url) else 0
    except:
        return 0

def httpSecure(url):
    try:
        return 1 if urlparse(url).scheme == 'https' else 0
    except:
        return 0

def digit_count(url):
    return sum(char.isdigit() for char in url)

def letter_count(url):
    return sum(char.isalpha() for char in url)

def Shortining_Service(url):
    pattern = r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"               r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"               r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"               r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"               r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"               r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"               r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"               r"tr\.im|link\.zip\.net)"
    try:
        return 1 if re.search(pattern, url) else 0
    except:
        return 0

def having_ip_address(url):
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    try:
        return 1 if re.search(ip_pattern, url) else 0
    except:
        return 0

def process_url(url):
    features = {}
    features['url_len'] = len(url)
    special_chars = ['@','?','-','=','.', '#','%','+','$','!','*',',','//']
    for char in special_chars:
        features[char] = url.count(char)
    features['abnormal_url'] = abnormal_url(url)
    features['https'] = httpSecure(url)
    features['digits'] = digit_count(url)
    features['letters'] = letter_count(url)
    features['Shortining_Service'] = Shortining_Service(url)
    features['having_ip_address'] = having_ip_address(url)
    return pd.DataFrame([features])

@app.route("/predict", methods=["POST"])
def predict_url():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No input data provided"}), 400
            
        url = data.get("url")
        if not url or not isinstance(url, str):
            return jsonify({"error": "Invalid or missing 'url' field"}), 400

        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            features = process_url(url)
            prediction = model.predict(features)[0]
        except Exception as e:
            return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

        labels = ["Safe", "Defacement", "Phishing", "Malware"]
        if prediction < 0 or prediction >= len(labels):
            return jsonify({"error": "Invalid prediction result"}), 500

        return jsonify({
            "input_url": url,
            "prediction": labels[prediction],
            "status": "success"
        })

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy"}), 200

# Run the app
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)


# In[ ]:




