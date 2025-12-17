import time
from datetime import datetime
import streamlit as st
import vt
import requests as rq
from fpdf import FPDF

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

# ----------------------------- دالة توليد PDF -----------------------------
def generate_pdf(target, scan_type, final_status, table_data):
    """
    تولد PDF في الذاكرة ثم تعيده بايتس جاهزة للتحميل.
    target: URL أو اسم الملف
    scan_type: "URL Scan" أو "File Scan" أو "Google Scan"
    final_status: "Safe" / "Dangerous" / "Error"
    table_data: قائمة صفوف تحتوي على مفاتيح: engine, Category, status
    """
    pdf = FPDF()
    pdf.add_page()

    # عنوان
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Trust Scan Report", ln=True, align="C")
    pdf.ln(4)

    # معلومات عامة
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"Type: {scan_type}", ln=True)
    pdf.cell(0, 8, f"Target: {target}", ln=True)
    pdf.cell(0, 8, f"Final status: {final_status}", ln=True)
    pdf.cell(0, 8, f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(6)

    # جدول النتائج
    pdf.set_font("Arial", "B", 12)
    pdf.cell(70, 8, "Engine", 1)
    pdf.cell(80, 8, "Category", 1)
    pdf.cell(30, 8, "Status", 1, ln=True)

    pdf.set_font("Arial", size=11)
    if not table_data:
        pdf.cell(180, 8, "No detailed results available.", 1, ln=True)
    else:
        for row in table_data:
            engine = str(row.get("engine", ""))[:40]
            category = str(row.get("Category", ""))[:60]
            status = str(row.get("status", ""))
            pdf.cell(70, 8, engine, 1)
            pdf.cell(80, 8, category, 1)
            pdf.cell(30, 8, status, 1, ln=True)

    # تحويل لسلسلة بايتات (latin-1 لتجنب مشاكل الحروف من FPDF)
    pdf_bytes = pdf.output(dest="S").encode("latin-1")
    return pdf_bytes

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
                json=data,
                timeout=20
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
            try:
                # حاول الحصول على تقرير موجود مسبقًا
                url_obj = client.get_url_report(URL)
            except Exception:
                # وإلا شغّل فحص جديد مع مؤشِّر انتظار
                with st.spinner("🛡️ VirusTotal is scanning the URL..."):
                    url_obj = client.scan_url(URL, wait_for_completion=True)

            # استخراج نتائج المحركات (يتوافق مع إصدارات vt مختلفة)
            if hasattr(url_obj, "last_analysis_results"):
                results_dict = url_obj.last_analysis_results
            elif hasattr(url_obj, "results"):
                results_dict = url_obj.results
            else:
                results_dict = {}

            for engine, details in results_dict.items():
                try:
                    category = details.get("category", "undetected").lower()
                except Exception:
                    category = str(details).lower()

                status = "dangerous" if any(word in category for word in danger_words) else "safe"
                if status == "dangerous":
                    is_dangerous = True
                tables.append({"engine": engine, "Category": category, "status": status})

            if not tables:
                tables.append({
                    "engine": "VirusTotal summary",
                    "Category": "Malicious: 0, Suspicious: 0, Harmless: 0, Undetected: 0",
                    "status": "safe"
                })

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
        tables = []

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

        # إعداد بيانات PDF للتحميل
        # إذا توجد نتائج VirusTotal استخدمها، وإلا أنشئ صف من Google فقط
        if tables:
            pdf_bytes = generate_pdf(URL, "URL Scan (VirusTotal)", status_v, tables)
            st.download_button(
                label="📄 Download PDF report",
                data=pdf_bytes,
                file_name=f"trustscan_url_{int(time.time())}.pdf",
                mime="application/pdf"
            )
        elif status_g:
            # لا توجد نتائج محركات لكن عندنا نتيجة من Google
            table_google = [{
                "engine": "Google Safe Browsing",
                "Category": status_g,
                "status": status_g.lower()
            }]
            pdf_bytes = generate_pdf(URL, "URL Scan (Google Safe Browsing)", status_g, table_google)
            st.download_button(
                label="📄 Download PDF report (Google)",
                data=pdf_bytes,
                file_name=f"trustscan_google_{int(time.time())}.pdf",
                mime="application/pdf"
            )

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
                        with st.spinner("🛡️ VirusTotal is scanning the file..."):
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

                    # زر تنزيل PDF لنتيجة الفحص
                    pdf_bytes = generate_pdf(uploaded_file.name, "File Scan", tables[0]["status"], tables)
                    st.download_button(
                        label="📄 Download PDF report",
                        data=pdf_bytes,
                        file_name=f"trustscan_file_{int(time.time())}.pdf",
                        mime="application/pdf"
                    )

                except Exception as e:
                    st.error(f"File scan failed: {e}")
