import streamlit as st
import vt
import requests as rq
from fpdf import FPDF
from datetime import datetime

# ----------------------------- إعداد الصفحة -----------------------------
st.set_page_config(
    page_title="Trust Scan",
    page_icon="🛡️"
)

tab1, tab2 = st.tabs(["Scan URL", "Scan File"])

API_KEY_google = st.secrets["API_google"]
API_KEY_virustotal = st.secrets["API_virus_total"]

danger_words = [
    "malicious", "phishing", "malware", "trojan",
    "harmful", "suspicious", "spam", "dangerous"
]

# ----------------------------- دالة إنشاء PDF -----------------------------
def create_pdf(url, status, tables=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"scan_report_{timestamp}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt="TrustScan Report", ln=True, align="C")
    pdf.ln(5)

    pdf.cell(0, 10, txt=f"URL/File: {url}", ln=True)
    pdf.cell(0, 10, txt=f"Status: {status}", ln=True)
    pdf.ln(5)

    if tables:
        pdf.cell(0, 10, txt="VirusTotal Details:", ln=True)
        for row in tables:
            line = f"Engine: {row['engine']} | Category: {row['Category']} | Status: {row['status']}"
            pdf.multi_cell(0, 10, line)

    pdf.output(file_name)
    return file_name

# ----------------------------- فحص Google Safe Browsing -----------------------------
def scan_vt(URL):
    client = vt.Client(API_KEY_virustotal)
    tables = []
    is_dangerous = False

    try:
        with st.spinner("Scanning VirusTotal..."):
            analysis = client.scan_url(URL, wait_for_completion=True)

            # ننتظر اكتمال التحليل
            while True:
                result = client.get_object(f"/analyses/{analysis.id}")
                if result.status == "completed":
                    break

        # الآن نستخدم نتيجة التحليل نفسها
        vt_results = result.results

        for engine, details in vt_results.items():
            category = details['category'].lower()
            is_engine_dangerous = any(word in category for word in danger_words)
            status = "dangerous" if is_engine_dangerous else "safe"

            if is_engine_dangerous:
                is_dangerous = True

            tables.append({
                "engine": engine,
                "Category": category,
                "status": status
            })

        # عرض النتيجة
        if is_dangerous:
            st.markdown("<h4 style='color: red;'>⚠ Dangerous</h4>", unsafe_allow_html=True)
        else:
            st.markdown("<h4 style='color: green;'>✔ Safe</h4>", unsafe_allow_html=True)

        st.table(tables)
        return ("Dangerous" if is_dangerous else "Safe"), tables

    except Exception as e:
        st.write(e)
# ----------------------------- فحص VirusTotal (الإصدار المحسّن) -----------------------------
def scan_vt(URL):
    client = vt.Client(API_KEY_virustotal)
    tables = []
    is_dangerous = False

    try:
        with st.spinner("Scanning VirusTotal..."):
            analysis = client.scan_url(URL, wait_for_completion=True)

            # ننتظر اكتمال التحليل
            while True:
                result = client.get_object(f"/analyses/{analysis.id}")
                if result.status == "completed":
                    break

            # جلب التقرير النهائي
            url_id = vt.url_id(URL)
            final_report = client.get_object(f"/urls/{url_id}")

        # استخراج النتائج
        for engine, details in final_report.last_analysis_results.items():
            category = details['category'].lower()
            is_engine_dangerous = any(word in category for word in danger_words)
            status = "dangerous" if is_engine_dangerous else "safe"

            if is_engine_dangerous:
                is_dangerous = True

            tables.append({
                "engine": engine,
                "Category": category,
                "status": status
            })

        # عرض النتيجة
        if is_dangerous:
            st.markdown("<h4 style='color: red;'>⚠ Dangerous</h4>", unsafe_allow_html=True)
        else:
            st.markdown("<h4 style='color: green;'>✔ Safe</h4>", unsafe_allow_html=True)

        st.table(tables)
        return ("Dangerous" if is_dangerous else "Safe"), tables

    except Exception as e:
        st.write(e)

# ----------------------------- واجهة فحص URL -----------------------------
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
        tables = None

        if choose == "🛡️ VirusTotal Scan":
            status_v, tables = scan_vt(URL)
            file_name = create_pdf(URL, status_v, tables=tables)

        elif choose == "🔍 Google Safe Browsing Scan":
            status_g = scan_g(URL)
            file_name = create_pdf(URL, status_g)

        elif choose == "Both (Deep Scan)":
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("🔍 Google Safe Browsing")
                status_g = scan_g(URL)
            with col2:
                st.subheader("🛡️ VirusTotal Scan")
                status_v, tables = scan_vt(URL)

            status_text = f"Google: {status_g}, VirusTotal: {status_v}"
            file_name = create_pdf(URL, status_text, tables=tables)

        # زر تحميل PDF
        with open(file_name, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name=file_name,
                mime="application/pdf"
            )

# ----------------------------- واجهة فحص الملفات -----------------------------
with tab2:
    st.title("Scan Your File")
    max_file = 30
    uploaded_file = st.file_uploader("Choose your file:", type=None)

    if uploaded_file:
        size = uploaded_file.size / (1024 * 1024)
        if size > max_file:
            st.error(f"❌ The file is too big. Maximum allowed size is {max_file} MB")
        else:
            if st.button("Start File Scanning"):
                with vt.Client(API_KEY_virustotal) as client:
                    analysis = client.scan_file(uploaded_file, wait_for_completion=True)

                stats = analysis.stats
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)

                if malicious > 0:
                    st.error("⚠ It's a malicious file")
                    status_file = "Malicious"
                elif suspicious > 0:
                    st.warning("⚠ It's a suspicious file")
                    status_file = "Suspicious"
                elif undetected > 0 and harmless > 0:
                    st.success("✔ It is safe")
                    status_file = "Safe"
                else:
                    st.info("ℹ File unknown, likely safe")
                    status_file = "Unknown"

                file_name = create_pdf(uploaded_file.name, status_file)
                with open(file_name, "rb") as f:
                    st.download_button(
                        label="Download PDF Report",
                        data=f,
                        file_name=file_name,
                        mime="application/pdf"
                    )

