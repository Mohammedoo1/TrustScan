import time
import streamlit as st
import vt
import requests as rq

st.set_page_config(
    page_title="TrustScan",
    page_icon="🛡️",
    layout="wide"
)

tab1, tab2 = st.tabs(["               Scan URL               ", "               Scan File              "])

API_KEY_google = st.secrets["API_google"]
API_KEY_virustotal = st.secrets["API_virus_total"]

# كلمات الخطر لتصنيف ناتج كل محرك
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


with tab1:
    st.title("Scan URL")
    URL = st.text_input("enter your URL :")

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
            with st.spinner("Scanning with Google Safe Browsing..."):
                response = rq.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_google}",
                    json=data,
                    timeout=15
                )

            result = response.json()

            if "matches" in result:
                st.error("⚠ Dangerous (Google Safe Browsing)")
                return "dangerous"
            else:
                st.success("✔ Safe (Google Safe Browsing)")
                return "safe"

        except Exception as e:
            st.error(f"Google scan failed: {e}")
            return "error"

    def scan_vt_url(URL):
        """فحص URL باستخدام VirusTotal — مع ملخص إذا كانت النتائج التفصيلية غير متاحة"""
        tables = []
        is_dangerous = False

        try:
            with vt.Client(API_KEY_virustotal) as client:
                with st.spinner("Scanning with VirusTotal..."):
                    analysis = client.scan_url(URL, wait_for_completion=True)

                # نحاول جلب تفاصيل التحليل (قد تكون dict أو object حسب المكتبة)
                result = client.get_object(f"/analyses/{analysis.id}")

                # محاولة استخراج results بأكثر من شكل
                def get_results_map(obj):
                    if isinstance(obj, dict):
                        return obj.get("results", {}) or {}
                    else:
                        return getattr(obj, "results", {}) or {}

                res_map = get_results_map(result)

                # إذا كانت النتائج التفصيلية فارغة، نمنح فرص بسيطة (retry) لأن بعض المحركات ترجع متأخرة
                attempts = 0
                while not res_map and attempts < 3:
                    time.sleep(1)  # تأخير بسيط
                    result = client.get_object(f"/analyses/{analysis.id}")
                    res_map = get_results_map(result)
                    attempts += 1

                # إذا بقيت النتائج فارغة نعتمد على stats (الملخص)
                if not res_map:
                    # قد تكون الإحصاءات في analysis أو في result
                    stats = {}
                    if hasattr(analysis, "stats") and analysis.stats:
                        stats = analysis.stats
                    elif isinstance(result, dict) and result.get("stats"):
                        stats = result.get("stats", {})
                    else:
                        stats = getattr(result, "stats", {}) or {}

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)

                    status = "safe" if malicious == 0 and suspicious == 0 else "dangerous"
                    tables.append({
                        "engine": "VirusTotal summary",
                        "Category": f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}",
                        "status": status
                    })

                    if status == "dangerous":
                        st.error("⚠ Dangerous (VirusTotal summary)")
                    else:
                        st.success("✔ Safe (VirusTotal summary)")

                    st.table(tables)
                    return status

                # لو فيه نتائج لكل محرك نعرضهم واحد واحد
                for engine, details in res_map.items():
                    # تفاصيل المحرك قد تكون dict مختلفة البنية، نحاول استخراج التصنيف
                    try:
                        results_text = details.get('category', str(details)).lower()
                    except Exception:
                        results_text = str(details).lower()

                    is_engine_dangerous = any(word in results_text for word in danger_words)
                    if is_engine_dangerous:
                        tables.append({"engine": engine, "Category": results_text, "status": "dangerous"})
                        is_dangerous = True
                    else:
                        tables.append({"engine": engine, "Category": results_text, "status": "safe"})

                if is_dangerous:
                    st.error("⚠ Dangerous (VirusTotal engines)")
                else:
                    st.success("✔ Safe (VirusTotal engines)")
                st.table(tables)
                return "dangerous" if is_dangerous else "safe"

        except Exception as e:
            st.error(f"VirusTotal scan failed: {e}")
            return "error"


    choose = st.radio(
        "choose where you want to check your link :",
        ["🛡️ VirusTotal Scan", "🔍 Google Safe Browsing Scan", "Both (for deep scan)"]
    )

    if st.button("start scanning"):
        if not URL:
            st.warning("❌ Please enter a URL before scanning.")
            st.stop()
        elif URL and not (URL.startswith("https://") or URL.startswith("http://")):
            st.error("Enter a valid URL (must start with http:// or https://)")
            st.stop()

        if choose == "🛡️ VirusTotal Scan":
            scan_vt_url(URL)

        elif choose == "🔍 Google Safe Browsing Scan":
            scan_g(URL)

        elif choose == "Both (for deep scan)":
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("🔍 Google Safe Browsing")
                status_g = scan_g(URL)
            with col2:
                st.subheader("🛡️ VirusTotal Scan")
                status_v = scan_vt_url(URL)
            if status_g != status_v and status_g != "error" and status_v != "error":
                st.warning("⚠ Maybe it is risky, don't open it")


with tab2:
    st.title("Scan your File")
    max_file = 30  # MB
    uploaded_file = st.file_uploader("Choose your file :", type=None)

    if uploaded_file is not None:
        size = uploaded_file.size / (1024 * 1024)
        st.write(f"File size: {size:.2f} MB")
        if size < max_file:
            if st.button("click me to scan"):
                try:
                    with st.spinner("Scanning file with VirusTotal..."):
                        with vt.Client(API_KEY_virustotal) as client:
                            analysis = client.scan_file(uploaded_file, wait_for_completion=True)

                    # نحاول قراءة stats من analysis أو من object الإضافي
                    stats = {}
                    if hasattr(analysis, "stats") and analysis.stats:
                        stats = analysis.stats
                    else:
                        # بعض الإصدارات ترجع dict
                        stats = getattr(analysis, "stats", {}) or {}

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)
                    harmless = stats.get("harmless", 0)

                    # نعرض جدول ملخص دائماً
                    summary_table = [{
                        "engine": "VirusTotal summary",
                        "Category": f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}",
                        "status": "dangerous" if (malicious > 0 or suspicious > 0) else "safe"
                    }]
                    if malicious > 0:
                        st.error("⚠ It's a malicious file (VirusTotal)")
                    elif suspicious > 0:
                        st.warning("⚠ It's a suspicious file (VirusTotal)")
                    else:
                        st.success("✔ It seems safe (VirusTotal summary)")

                    st.table(summary_table)

                except Exception as e:
                    st.error(f"File scan failed: {e}")

        else:
            st.error(f"❌ The file is too big. Maximum allowed size is {max_file} MB")
