# 🛡️ AI Cyber Threat Analysis Platform

An AI-assisted cybersecurity investigation platform designed to analyze suspicious digital artifacts, identify threat indicators, correlate security findings, and support incident-response investigations.

## 🚀 Project Overview

The AI Cyber Threat Analysis Platform combines **AI-based detection, rule-based security analysis, threat intelligence, IOC investigation, correlation, and incident-response support** in one application.

It can analyze multiple types of security artifacts and provide understandable security findings and risk information.

## 🔍 Key Features

### 🔗 URL Threat Scanner
- AI-based phishing URL detection
- HTTPS analysis
- Suspicious keyword detection
- IP-based URL detection
- Domain and subdomain analysis
- Risk scoring
- AI confidence

### 📁 File Threat Analyzer
- File metadata analysis
- SHA-256 fingerprinting
- Entropy analysis
- Suspicious pattern detection
- Risk classification

### 📧 Email Threat Analyzer
- Suspicious keyword detection
- URL extraction
- Suspicious link analysis
- Security indicator detection
- Email risk classification

### 📱 QR Threat Scanner
- QR code detection
- QR content extraction
- URL analysis from QR codes

### 🌐 Domain/IP Intelligence
- DNS resolution
- IP detection
- Domain analysis
- Suspicious domain indicators
- Risk assessment

### 🦠 Malware Intelligence
- Malware-oriented artifact analysis
- Threat indicators
- Possible malware classifications
- Security recommendations

### 🔗 Threat Correlation
- Correlates related security artifacts
- Detects shared domains
- Detects repeated fingerprints
- Connects related investigations

### 🚨 Incident Response Center
- Incident severity assessment
- Threat priority scoring
- Immediate response actions
- Containment steps
- Investigation steps

### 🧠 Threat Intelligence
- Threat reputation assessment
- Intelligence confidence
- Threat identification
- Security recommendations

### 🔎 IOC Extraction & Investigation
Extracts:
- URLs
- Domains
- IPv4 addresses
- MD5
- SHA-1
- SHA-256

### 🕵️ IOC Investigation Dashboard
Provides investigation summaries and prioritization based on extracted indicators.

### 🔗 IOC Relationship & Correlation
Builds relationships between:
- URLs
- Domains
- IP addresses
- File hashes
- Previous investigations

### 🕸️ Threat Graph Visualization
Visualizes relationships between discovered security indicators.

### 📊 Investigation Statistics
Provides investigation and scan statistics.

### 📜 Scan History
Maintains previous analysis results during the application session.

## 🧠 AI Detection

The URL detection component uses a machine-learning model trained using the **PhiUSIIL Phishing URL Dataset**.

The dataset was used during model development and training and is **not required to run the deployed application**.

The trained model and vectorizer are included with the application.

## 🛠️ Technologies Used

- Python
- Streamlit
- Pandas
- Scikit-learn
- Joblib
- OpenCV
- ReportLab
- DNS / networking libraries
- Machine Learning
- Threat Intelligence
- IOC Analysis

## 🏗️ Project Architecture

```text
User Input
    │
    ├── URL
    ├── File
    ├── Email
    ├── QR Code
    └── Domain / IP
            │
            ▼
     Security Analysis
            │
            ▼
      AI + Rule Engine
            │
            ▼
      Threat Indicators
            │
            ▼
       Risk Assessment
            │
            ▼
    Threat Intelligence
            │
            ▼
    IOC Extraction
            │
            ▼
      Correlation Engine
            │
            ▼
    Incident Response
            │
            ▼
      Security Report