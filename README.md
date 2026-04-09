# Phishing Website Detection Tool 🔍🛡️  

A sophisticated web application that identifies phishing websites using a hybrid detection system combining rule-based analysis and machine learning.   
  
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)   
![Flask](https://img.shields.io/badge/Flask-2.0%2B-lightgrey)
![Machine Learning](https://img.shields.io/badge/ML-Random%20Forest-orange)
![License](https://img.shields.io/badge/License-MIT-green)
  
🧠 Problem Statement

Phishing attacks are one of the most common online threats used to steal sensitive information like login credentials, banking details, and personal data. Detecting phishing websites accurately and efficiently can help protect users and organizations.

This project builds a model that classifies website URLs as phishing or legitimate, and exposes it through a simple web UI for real-time prediction.

🚀 Features 

✔ Uses real URL feature data to train a model
✔ Predicts whether a website is phishing or safe
✔ Flask web interface for user input
✔ Interactive UI to test new URLs
✔ Easy to use and deploy
 
📊 Tech Stack
Layer	Tools / Libraries
Backend	Python, Flask
ML	scikit-learn, pandas, NumPy
Model	RandomForestClassifier (recommended)
UI	HTML, CSS, Bootstrap
Deployment	Local / Flask server
 
📥 Dataset 
 
The dataset comes from a public URL classification dataset commonly used for phishing detection research. It contains:

✔ URL strings
✔ Features extracted from URLs
✔ Labels indicating phishing (1) or legitimate (0)

You can find the dataset source in the training notebook (phishing_website.ipynb).

📊 Model and Evaluation

The model used here (RandomForestClassifier) is chosen because it balances performance and interpretability.

Evaluation Metrics (example):

Metric	Score
Accuracy	94%
Precision	92%
Recall	90%
F1-Score	91%

These scores indicate the model predicts phishing websites accurately with minimal false positives.

🧪 How to Run Locally
🔹 Step 1 – Clone the repo
git clone https://github.com/Kushal-29/phishing-website-detector.git
cd phishing-website-detector

🔹 Step 2 – Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows

🔹 Step 3 – Install dependencies
pip install -r requirements.txt

🔹 Step 4 – Run the app
python phishing_detector.py

🔹 Step 5 – Open in Browser

Open your browser and go to:

http://127.0.0.1:5000


Enter a URL to test if it’s phishing or legit.
