# 🛡 Real-Time Phishing Website Detection Using Machine Learning

A hybrid phishing detection system that combines heuristic URL analysis with a LightGBM-based machine learning model to classify websites as **Safe**, **Suspicious**, or **Phishing** in real time.

This system is deployed as:

- 🔌 Chrome Extension (User Interface)
- ⚙ FastAPI Backend (API & ML Inference)
- 🤖 LightGBM Model (Binary Classification)
- 📊 Admin Feedback Dashboard

---

# 📌 Project Overview

Phishing attacks continue to increase in scale and sophistication. Traditional blacklist-based detection systems are reactive and fail to detect newly generated or short-lived phishing domains.

This project proposes a **hybrid detection framework** that integrates:

- Heuristic URL validation
- Machine Learning classification
- Risk score generation (0–100)
- Real-time browser deployment

---

# 🏗 System Architecture

User → Chrome Extension / Web Interface  
↓  
FastAPI Backend  
↓  
Heuristic Engine  
↓  
Feature Extraction  
↓  
LightGBM Model  
↓  
Risk Score + Classification  

---

# 🔍 Key Features

- Unicode homoglyph attack detection
- Typosquatting detection
- IP-based URL detection
- Free hosting abuse detection
- Blacklist validation (OpenPhish + PhishTank)
- Feature-based URL analysis
- Risk score interpretation (0–100)
- Admin-only feedback dashboard
- Real-time Chrome extension integration

---

# 📊 Model Performance

- Total Dataset Size: ~202,600 URLs
- Train-Test Split: 80–20
- Training Samples: ~162,000
- Test Samples: ~40,600

### Test Results:
- Accuracy: 95.8%
- ROC-AUC: 0.9938
- PR-AUC: 0.9957

Model evaluated strictly on held-out test data.

---

# 🛠 Technologies Used

## Backend
- FastAPI
- Uvicorn
- Python

## Machine Learning
- LightGBM
- Scikit-learn
- Pandas
- NumPy
- SHAP (Model Explainability)
- Joblib

## Threat Intelligence
- OpenPhish
- PhishTank

## Frontend
- Chrome Extension (HTML, CSS, JavaScript)

---

# 📁 Project Structure

```
PHISHING_DETECTION_PROJECT/
│
├── backend/
│   ├── app.py
│   ├── ml_model.py
│   ├── openphish.py
│   ├── phishtank.py
│   ├── requirements.txt
│   └── model/
│
├── chrome_extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── background.js
│   ├── feedback.html
│   ├── feedback.js
│   └── icons/
│
├── ml/
│   ├── train_model.py
│   ├── evaluate_model.py
│   ├── feature_extraction.py
│   └── dataset/
│
├── README.md
└── .gitignore
```

---

# 🚀 Setup Instructions

---

## 🔹 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/real-time-phishing-detection.git
cd real-time-phishing-detection
```

---

## 🔹 2. Create Virtual Environment

```bash
python -m venv venv
```

Activate:

Windows:
```
venv\Scripts\activate
```

Mac/Linux:
```
source venv/bin/activate
```

---

## 🔹 3. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

---

# 📂 Dataset Setup Guide

⚠ Datasets are NOT included due to size limitations.

You must download and prepare them manually.

---

## 📥 Step 1: Download Phishing URLs

Download from:

OpenPhish:
https://openphish.com/feed.txt

PhishTank:
https://phishtank.org/developer_info.php

Save as:

```
ml/dataset/phishing_urls.csv
```

Required format:

```csv
url,label
http://fake-login.com,1
http://malicious-site.com,1
```

Label:
1 → Phishing

---

## 📥 Step 2: Download Legitimate URLs

You can use:

- Tranco Top Sites
- Majestic Million
- Alexa Top Sites
- Kaggle datasets

Save as:

```
ml/dataset/legitimate_urls.csv
```

Required format:

```csv
url,label
http://google.com,0
http://amazon.com,0
```

Label:
0 → Legitimate

---

## 📁 Step 3: Folder Structure Must Be

```
ml/
 └── dataset/
      ├── phishing_urls.csv
      └── legitimate_urls.csv
```

---

## 🧠 Step 4: Train Model

```bash
cd ml
python train_model.py
```

This will:

- Extract features
- Train LightGBM model
- Save model to:

```
backend/model/lightgbm_model.pkl
```

---

# ▶ Run Backend Server

```bash
cd backend
uvicorn app:app --reload
```

Server URL:
```
http://127.0.0.1:8000
```

Swagger API Docs:
```
http://127.0.0.1:8000/docs
```

---

# 🔌 Chrome Extension Setup

1. Open Chrome
2. Go to:
   ```
   chrome://extensions
   ```
3. Enable Developer Mode
4. Click "Load Unpacked"
5. Select `chrome_extension/` folder

---

# 🔐 Admin Feedback Dashboard

Accessible via:

```
chrome-extension://<EXTENSION_ID>/feedback.html
```

Default Password:
```
admin@phishguard
```

Feedback is stored in:
```
chrome.storage.local
```

Admin dashboard provides:
- Total feedback count
- Helpful vs Not Helpful metrics
- Accuracy per category
- CSV/JSON export

---

# 🌐 Optional Web Interface Integration

The backend API can also be integrated into a full-stack web application using:

POST /check-url

Example Request:
```json
{
  "url": "http://example.com"
}
```

Response:
```json
{
  "status": "safe",
  "final_risk_score": 12,
  "reasons": [...]
}
```

---

# 🧠 Detection Categories

Risk Score Interpretation:

- 0–39 → Safe
- 40–69 → Suspicious
- 70–100 → Phishing

---

# 📈 Future Improvements

- WHOIS-based domain age detection
- Real-time cloud deployment
- Continuous retraining pipeline
- Deep learning experimentation
- API authentication layer

---

# 👨‍💻 Team

- Dinesh Pandian G  
- Ram Pandian G  
- Ragulraj S  

Mentor:
Mrs. M. Thulasi Devi  

Conference:
ICICSDF’26  

---

# 📄 License

Developed for academic and research purposes.