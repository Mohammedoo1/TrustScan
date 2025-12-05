TrustScan 🛡️

TrustScan is a simple tool that allows you to scan **URLs and files** to check if they are safe or dangerous.  
It uses **Google Safe Browsing** and **VirusTotal** to detect malware, phishing, and harmful websites.

---
🚀 Features
- Scan any URL (website link).  
- Scan files up to **30 MB**.  
- Choose between:
  - Google Safe Browsing Scan  
  - VirusTotal Scan  
  - Both (deep scan)
- Shows a clear result:
  - Safe  
  - Suspicious  
  - Malicious  
- Simple and clean Streamlit interface.

---
🛠️ Installation
Install the required libraries:

All required libraries are listed in the `requirements.txt` file.  

These are them :

```
pip install streamlit
pip install vt-py
pip install request
```
---
API Setup 🔑

TrustScan requires API keys to work:

1. **Google Safe Browsing API**
   - Go to [Google Cloud Console](https://console.cloud.google.com/).  
   - Create a new project (or use an existing one).  
   - Enable the **Safe Browsing API**.  
   - Generate an **API key**.  

2. **VirusTotal API**
   - Go to [VirusTotal](https://www.virustotal.com/) and **sign up / log in**.  
   - Go to your profile → API Key section.  
   - Copy your **personal API key*


*Running the Project:*


To run TrustScan on your local machine:

Open a terminal inside the project folder.

Make sure you have added your API keys (see instructions above).


Run the following command:

```
streamlit run app.py
```

Replace ``` app.py ``` with the actual name of your main Python file if it is different.


