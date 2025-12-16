import streamlit as st
import vt
import requests as rq

# ------------------ إعداد الصفحة ------------------
st.set_page_config(
    page_title="TrustScan",
    page_icon="🛡️"
)

tab1, tab2 = st.tabs(
    ["       🔗 Scan URL       ", "       📁 Scan File       "]
)

API_KEY_google = st.secrets["API_google"]
API_KEY_virustotal = st.secrets["API_virus_total"]

# ------------------ دالة Google Safe Browsing ------------------
def scan_google(URL):
    try:
        data = {
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": URL}]
            }
        }

        with st.spinner("🔍 Google Safe Browsing scanning..."):
            response = rq.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_google}",
                json=data
            )

        result = response.json()

        if "matches" in result:
            st.error("⚠ Dangerous (Google Safe Browsing)")
            return "dangerous"
        else:
            st.success("✔ Safe (Google Safe Browsing)")
            return "safe"

    except Exception as e:
        st.error(e)


# ------------------ دالة VirusTotal URL ------------------
def scan_virustotal_url(URL):
    tables = []
    is_dangerous = False

    try:
        with vt.Client(API_KEY_virustotal) as client:
            with st.spinner("🛡️ VirusTotal scanning..."):
                analysis = client.scan_url(URL, wait_for_completion=True)

        for engine, details in analysis.results.items():
            category = details["category"].lower()

            if category in ["malicious", "suspicious"]:
                tables.append({
                    "Engine": engine,
                    "Category": category,
                    "Status": "dangerous"
                })
                is_dangerous = True
            else:
                tables.append({
                    "Engine": engine,
                    "Category": category,
                    "Status": "safe"
                })

        st.table(tables)

        if is_dangerous:
            st.error("⚠ Dangerous (VirusTotal)")
            return "dangerous"
        else:
            st.success("✔ Safe (VirusTotal)")
            return "safe"

    except Exception as e:
        st.error(e)


# ================== TAB 1 : Scan URL ==================
with tab1:
    st.title("🔗 Scan URL")
    URL = st.text_input("Enter URL (with http/https):")

    choose = st.radio(
        "Choose scan method:",
        [
            "🛡️ VirusTotal",
            "🔍 Google Safe Browsing",
            "🔎 Both (Deep Scan)"
        ]
    )

    if st.button("🚀 Start Scanning"):
        if not URL:
            st.warning("❌ Please enter a URL")
            st.stop()

        if not URL.startswith(("http://", "https://")):
            st.error("❌ Invalid URL format")
            st.stop()

        if choose == "🛡️ VirusTotal":
            scan_virustotal_url(URL)

        elif choose == "🔍 Google Safe Browsing":
            scan_google(URL)

        elif choose == "🔎 Both (Deep Scan)":
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("🔍 Google Safe Browsing")
                status_g = scan_google(URL)

            with col2:
                st.subheader("🛡️ VirusTotal")
                status_v = scan_virustotal_url(URL)

            if status_g != status_v:
                st.warning("⚠ The link may be risky. Be careful!")

# ================== TAB 2 : Scan File ==================
with tab2:
    st.title("📁 Scan File (VirusTotal)")
    MAX_FILE_MB = 30

    uploaded_file = st.file_uploader("Upload your file:")

    if uploaded_file:
        size_mb = uploaded_file.size / (1024 * 1024)

        if size_mb > MAX_FILE_MB:
            st.error(f"❌ File too large (Max {MAX_FILE_MB} MB)")
        else:
            if st.button("🛡️ Scan File"):
                try:
                    with vt.Client(API_KEY_virustotal) as client:
                        with st.spinner("Scanning file..."):
                            analysis = client.scan_file(
                                uploaded_file,
                                wait_for_completion=True
                            )

                    stats = analysis.stats

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)

                    if malicious > 0:
                        st.error("⚠ Malicious file")
                    elif suspicious > 0:
                        st.warning("⚠ Suspicious file")
                    elif harmless > 0:
                        st.success("✔ Safe file")
                    else:
                        st.info("ℹ Unknown file (no engine flagged it)")

                except Exception as e:
                    st.error(e)
