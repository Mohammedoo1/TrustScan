import time
import streamlit as st
import vt
import requests as rq
from datetime import datetime

# ----------------------------- إعداد الصفحة -----------------------------
st.set_page_config(
    page_title="Trust Scan",
    page_icon="🛡️",
    layout="wide"
)

tab1, tab2 = st.tabs(["Scan URL", "Scan File"])

API_KEY_google = st.secrets["API_google"]
API_KEY_virustotal = st.secrets["API_virus_total"]

# كلمات الخطر لتصنيف ناتج كل محرك
danger_words = [
    "malicious", "phishing", "malware", "trojan",
    "harmful", "suspicious", "spam", "dangerous"
]

# ----------------------------- وظائف الفحص -----------------------------
def scan_g(URL):
    """فحص سريع باستخدام Google Safe Browsing API"""
    try:
        data = {
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": URL}]
            }
        }
        with st.spinner("Scanning Google Safe Browsing..."):
            response = rq.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_google}",
                json=data
            )
        result = response.json()
        if "matches" in result:
            st.error("⚠ Dangerous (Google Safe Browsing)")
            return "Dangerous"
        else:
            st.success("✔ Safe (Google Safe Browsing)")
            return "Safe"
    except Exception as e:
        st.error(f"Google scan failed: {e}")
        return "Error"

def scan_vt(URL):
    """فحص URL باستخدام VirusTotal"""
    tables = []
    is_dangerous = False
    try:
        with vt.Client(API_KEY_virustotal) as client:
            # محاولة جلب تقرير موجود مسبقًا
            try:
                url_obj = client.get_url_report(URL)
            except:
                # إذا لا يوجد تقرير مسبق، نعمل فحص جديد
                url_obj = client.scan_url(URL, wait_for_completion=True)

            # استخراج نتائج المحركات
            if hasattr(url_obj, 'last_analysis_results'):
                results_dict = url_obj.last_analysis_results
            elif hasattr(url_obj, 'results'):
                results_dict = url_obj.results
            else:
                results_dict = {}

            for engine, details in results_dict.items():
                try:
                    category = details.get('category', 'undetected').lower()
                except Exception:
                    category = str(details).lower()

                status = "dangerous" if any(word in category for word in danger_words) else "safe"
                if status == "dangerous":
                    is_dangerous = True
                tables.append({"engine": engine, "Category": category, "status": status})

            # إذا لا توجد نتائج، نضيف صف ملخص مثل البرنامج الأول
            if not tables:
                tables.append({
                    "engine": "VirusTotal summary",
                    "Category": "Malicious: 0, Suspicious: 0, Harmless: 0, Undetected: 0",
                    "status": "safe"
                })

            # عرض الجدول
            st.table(tables)

            if is_dangerous:
                st.error("⚠ Dangerous (VirusTotal engines)")
            else:
                st.success("✔ Safe (VirusTotal engines)")

            return "Dangerous" if is_dangerous else "Safe", tables

    except Exception as e:
        st.error(f"VirusTotal scan failed: {e}")
        return "Error", tables

# ----------------------------- تبويب URL -----------------------------
with tab1:
    st.title("Scan URL")
    URL = st.text_input("Enter your URL:")

    choose = st.radio(
        "Choose where to check your link:",
        ["🛡️ VirusTotal Scan", "🔍 Google Safe Browsing Scan", "Both (Deep Scan)"]
    )

    if st.button("Start Scanning"):
        if not URL:
            st.warning("❌ Please enter a URL before scanning.")
            st.stop()
        elif not (URL.startswith("https://") or URL.startswith("http://")):
            st.error("Enter a valid URL (http:// or https://)")
            st.stop()

        status_g = status_v = None

        if choose == "🛡️ VirusTotal Scan":
            status_v, tables = scan_vt(URL)

        elif choose == "🔍 Google Safe Browsing Scan":
            status_g = scan_g(URL)

        elif choose == "Both (Deep Scan)":
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("🔍 Google Safe Browsing")
                status_g = scan_g(URL)
            with col2:
                st.subheader("🛡️ VirusTotal Scan")
                status_v, tables = scan_vt(URL)
            if status_g != status_v and status_g != "Error" and status_v != "Error":
                st.warning("⚠ Maybe it is risky, don't open it")

# ----------------------------- تبويب الملفات -----------------------------
with tab2:
    st.title("Scan Your File")
    max_file = 30  # MB
    uploaded_file = st.file_uploader("Choose your file:", type=None)
    if uploaded_file:
        size = uploaded_file.size / (1024 * 1024)
        st.write(f"File size: {size:.2f} MB")
        if size > max_file:
            st.error(f"❌ The file is too big. Maximum allowed size is {max_file} MB")
        else:
            if st.button("Start File Scanning"):
                try:
                    with vt.Client(API_KEY_virustotal) as client:
                        analysis = client.scan_file(uploaded_file, wait_for_completion=True)

                    stats = getattr(analysis, "stats", {}) or {}
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)
                    harmless = stats.get("harmless", 0)

                    tables = [{
                        "engine": "VirusTotal summary",
                        "Category": f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}",
                        "status": "dangerous" if (malicious > 0 or suspicious > 0) else "safe"
                    }]
                    st.table(tables)

                    if malicious > 0:
                        st.error("⚠ It's a malicious file")
                    elif suspicious > 0:
                        st.warning("⚠ It's a suspicious file")
                    else:
                        st.success("✔ It seems safe")

                except Exception as e:
                    st.error(f"File scan failed: {e}")
