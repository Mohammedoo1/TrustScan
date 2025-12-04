import streamlit as st
import vt
import requests as rq

st.set_page_config(
    page_title="TrustScan",
    page_icon="🛡️"
)

tab1,tab2 = st.tabs(["               Scan URL               ","               Scan Fill              "])

API_KEY = st.secrets["API_google"]
API = st.secrets["API_virus"]


with tab1:
    st.title(" Scan URL ")
    URL = st.text_input("enter your URl :")
    if not URL.startswith("https://") or not URL.startswith("http://"):
        st.error("Enter a valid URL")
        st.stop()
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
            with st.spinner("Scanning..."):
                analysis = client.scan_url(URL, wait_for_completion=True)
                result = client.get_object(f"/analyses/{analysis.id}")

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
                st.table(tables)

                return "dangerous"
            else:
                st.success("safe")
                st.table(tables)

                return "safe"

        except Exception as e:
            st.write(e)


    choose = st.radio(
        "choose where you want to check your link :",
        ["🛡️ VirusTotal Scan", "🔍 Google Safe Browsing Scan", "Both (for deep scan)"]
    )

    if st.button("start scanning"):
        if not URL:
            st.warning("❌ Please enter a URL before scanning.")
            st.stop()


        if choose == "🛡️ VirusTotal Scan":
            scan(URL)

        elif choose == "🔍 Google Safe Browsing Scan":
            scan_g(URL)

        elif choose == "Both (for deep scan)":
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("🔍 Google Safe Browsing")
                status_g = scan_g(URL)
            with col2:
                st.subheader("🛡️ VirusTotal Scan")
                status_v = scan(URL)
            if status_g != status_v:
                st.warning("⚠ Maybe it is risky, don't open it ")

with tab2:

    st.title("Scan your File")
    max_file=30
    uploaded_file = st.file_uploader("Choose ypur file :", type=None)
    if uploaded_file is not None:
        size= uploaded_file.size / (1024*1024)
        if size < max_file:
            if st.button("click me to scan"):
                with st.spinner("Scanning..."):
                    with vt.Client(API) as client:
                        analysis = client.scan_file(uploaded_file, wait_for_completion=True)

                stats = analysis.stats
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)

                if malicious > 0:
                   st.error("⚠ It's a malicious file")
                elif suspicious > 0:
                   st.warning("⚠ It's a suspicious file")
                elif undetected > 0 and harmless > 0:
                   st.success("✔ It is save")
                else:
                   st.info("ℹ No engine flagged it. The file is unknown but likely non-malicious ")
        elif size > max_file:
            st.error(f"❌ The file is too big. Maximum allowed size is {max_file} MB")











