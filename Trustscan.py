import streamlit as st
import vt
import requests as rq

st.set_page_config(
    page_title="TrustScan",
    page_icon="🛡️"
)

tab1, tab2 = st.tabs(["               Scan URL               ", "               Scan Fill              "])

API_KEY_google = st.secrets["API_google"]
API_KEY_virustotal = st.secrets["API_virus_total"]

with tab1:
    st.title(" Scan URL ")
    URL = st.text_input("enter your URl :")

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
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_google}",
                    json=data
                )

            result = response.json()

            if "matches" in result:
                st.error("⚠ Dangerous")
                return "dangerous"
            else:
                st.success("✔ Safe")
                return "safe"

        except Exception as e:
            st.write(e)

def scan(URL):
    client = vt.Client(API_KEY_virustotal)
    tables = []
    is_dangerous = False

    try:
        with st.spinner("Scanning..."):
            analysis = client.scan_url(URL, wait_for_completion=True)
            result = client.get_object(f"/analyses/{analysis.id}")

        # إذا كانت نتائج المحركات فارغة، نعتمد على stats
        if not getattr(result, "results", {}):
            stats = getattr(analysis, "stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            
            status = "safe" if malicious == 0 and suspicious == 0 else "dangerous"
            tables.append({
                "engine": "VirusTotal summary",
                "Category": f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}",
                "status": status
            })
            
            if status == "dangerous":
                st.error("⚠ Dangerous")
            else:
                st.success("✔ Safe")
            st.table(tables)
            return status

        for engine, details in result.results.items():
            results = details['category'].lower()
            is_engine_dangerous = any(word in results for word in danger_words)

            if is_engine_dangerous:
                tables.append({"engine": engine, "Category": results, "status": "dangerous"})
                is_dangerous = True
            else:
                tables.append({"engine": engine, "Category": results, "status": "safe"})

        if is_dangerous:
            st.error("⚠ Dangerous")
        else:
            st.success("✔ Safe")
        st.table(tables)
        return "dangerous" if is_dangerous else "safe"

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
        elif URL and not (URL.startswith("https://") or URL.startswith("http://")):
            st.error("Enter a valid URL")
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
    max_file = 30
    uploaded_file = st.file_uploader("Choose your file :", type=None)
    if uploaded_file is not None:
        size = uploaded_file.size / (1024 * 1024)
        if size < max_file:
            if st.button("click me to scan"):
                with st.spinner("Scanning..."):
                    with vt.Client(API_KEY_virustotal) as client:
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


















