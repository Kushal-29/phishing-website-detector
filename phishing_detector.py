import re
import pandas as pd
import joblib
from flask import Flask, render_template_string, request

app = Flask(__name__)

# Load ML model once at startup
try:
    model = joblib.load('phishing_rf_model.pkl')
except:
    model = None
    print("Warning: ML model not found. Only rule-based detection will work.")

# Feature extraction functions
def has_ip_address(url):
    ip_pattern = r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}'
    return int(bool(re.search(ip_pattern, url)))

def url_length(url):
    return len(url)

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_at_symbol(url):
    return url.count('@')

def count_question_mark(url):
    return url.count('?')

def count_equal_sign(url):
    return url.count('=')

def count_https(url):
    return int(url.startswith('https'))

def suspicious_words(url):
    keywords = ['secure', 'account', 'update', 'free', 'login', 'verify', 'bank', 'confirm']
    return int(any(word in url.lower() for word in keywords))

def double_slash_redirect(url):
    return int(url[8:].find('//') != -1)  # skip protocol

# Rule-based detection
def rule_based_detection(url):
    if has_ip_address(url):
        return True
    if count_at_symbol(url) > 0:
        return True
    if double_slash_redirect(url):
        return True
    if suspicious_words(url):
        return True
    if url_length(url) > 75:
        return True
    return False

# Predict function combining rule-based and ML
def predict_url(url):
    if rule_based_detection(url):
        return "Phishing (Rule-based)"
    if model:
        features = pd.DataFrame([{
            'has_ip': has_ip_address(url),
            'url_length': url_length(url),
            'dots': count_dots(url),
            'hyphens': count_hyphens(url),
            'at_symbol': count_at_symbol(url),
            'question_mark': count_question_mark(url),
            'equal_sign': count_equal_sign(url),
            'https': count_https(url),
            'suspicious_words': suspicious_words(url),
            'double_slash': double_slash_redirect(url)
        }])
        pred = model.predict(features)[0]
        return "Phishing (ML-based)" if pred == 1 else "Legitimate"
    else:
        return "Legitimate (No ML model loaded)"

# HTML template with simple CSS styling
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Phishing Website Detection Tool</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: rgba(0,0,0,0.6);
            padding: 30px 40px;
            border-radius: 15px;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        h1 {
            margin-bottom: 25px;
            font-weight: 700;
            letter-spacing: 1.2px;
        }
        input[type="text"] {
            width: 100%;
            padding: 15px 20px;
            border-radius: 50px;
            border: none;
            outline: none;
            font-size: 1.1rem;
            margin-bottom: 20px;
            box-sizing: border-box;
            transition: box-shadow 0.3s ease;
        }
        input[type="text"]:focus {
            box-shadow: 0 0 10px #9f7aea;
        }
        button {
            background: #9f7aea;
            border: none;
            padding: 15px 40px;
            border-radius: 50px;
            color: white;
            font-size: 1.1rem;
            cursor: pointer;
            transition: background 0.3s ease;
            font-weight: 600;
        }
        button:hover {
            background: #7f5fc5;
        }
        .result {
            margin-top: 25px;
            font-size: 1.3rem;
            font-weight: 700;
            padding: 15px;
            border-radius: 10px;
        }
        .phishing {
            background-color: #e53e3e;
            color: white;
        }
        .legitimate {
            background-color: #38a169;
            color: white;
        }
        footer {
            margin-top: 30px;
            font-size: 0.9rem;
            color: #ccc;
        }
        a {
            color: #9f7aea;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Phishing Website Detection Tool</h1>
        <form method="POST">
            <input type="text" name="url" placeholder="Enter URL here..." required autofocus />
            <br />
            <button type="submit">Check URL</button>
        </form>
        {% if result %}
            <div class="result {% if 'Phishing' in result %}phishing{% else %}legitimate{% endif %}">
                {{ result }}
            </div>
        {% endif %}
        <footer>
            Developed by YourName | <a href="https://www.tamizhanskills.com" target="_blank">Tamizhan Skills</a>
        </footer>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url.startswith('http'):
            url = 'http://' + url  # Add protocol if missing
        result = predict_url(url)
    return render_template_string(HTML_TEMPLATE, result=result)

if __name__ == '__main__':
    app.run(debug=True)
