
import streamlit as st
import vt
import requests as rq
API_KEY = API_google
API = API_virus

st.title(" Scan URL ")

URL = st.text_input("enter your URl :")

client = vt.Client(API)

danger_words = [
    "malicious",
    "phishing",
    "malware",
    "trojan",
    "harmful",
    "suspicious",
    "spam",
    "dangerous",
]
st.set_page_config(
    page_title="VirusTotal Safe Browsing",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def scan_g(URL):
    try:
        data = {
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": URL}]
            }
        }

        with st.spinner("Scanning..."):
            response = rq.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}",
                json=data
            )

        result = response.json()

        if "matches" in result:
            st.error("⚠ Google Safe Browsing: Dangerous")
            return "dangerous"
            st.write(result["matches"])
        else:
            st.success("✔ Google Safe Browsing: Safe")
            return "safe"

    except Exception as e:
        st.write(e)

def scan(URL):
    client = vt.Client(API)

    tables = []
    is_dangerous = False

    try:

        analysis = client.scan_url(URL)

        with st.spinner("Scanning..."):

            while True:
                result = client.get_object(f"/analyses/{analysis.id}")
                if result.status == "completed":
                    break

        st.write("Scan completed!")
        for engine, details in result.results.items():
            results = details['category'].lower()

            is_engine_dangerous = False
            for word in danger_words:
                if word in results:
                    is_engine_dangerous = True
                    break

            if is_engine_dangerous:
                tables.append({"engine": engine, "Category": results, "status": "dangerous"})
                is_dangerous = True

            else:
                tables.append({"engine": engine, "Category": results, "status": "safe"})

        if is_dangerous:
            st.error("dangerous")
            return "dangerous"

        else:
            st.success("safe")
            return "safe"
        st.table(tables)
    except :
         return "safe"
choose=st.radio("choose where you want to check your link :",["virous total" , "google", "both"])

if st.button("Click me to start scanning"):
    if choose == "virous total":
        scan(URL)
    elif choose == "google":
        scan_g(URL)
    elif choose == "both":
        col1 , col2 = st.columns(2)
        with col1:
            st.subheader("🔍 Google Safe Browsing")
            g = scan_g(URL)
        with col2:
            st.subheader("🛡️ VirusTotal Scan")
            v = scan(URL)
        if g != v:
            st.warning("⚠ Maybe it is risky, don't open it ")

