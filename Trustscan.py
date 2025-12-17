# app.py
import streamlit as st
import vt
import requests as rq
from fpdf import FPDF
from datetime import datetime
import pandas as pd

# ----------------------------- إعداد الصفحة -----------------------------
st.set_page_config(
    page_title="Trust Scan",
    page_icon="🛡️",
    layout="wide"
)

# ----------------------------- إعدادات البداية -----------------------------
if "is_scanning" not in st.session_state:
    st.session_state.is_scanning = False
if "history" not in st.session_state:
    st.session_state.history = []  # كل عنصر: dict {time, type, target, final_status, table}

API_KEY_google = st.secrets.get("API_google", "")
API_KEY_virustotal = st.secrets.get("API_virus_total", "")

# كلمات الخطر لتصنيف ناتج كل محرك
danger_words = [
    "malicious", "phishing", "malware", "trojan",
    "harmful", "suspicious", "spam", "dangerous"
]

# ----------------------------- دالة توليد PDF -----------------------------
def generate_pdf_bytes(target, scan_type, final_status, table_data):
    """تولّد PDF وتعيده بايتس جاهز للتحميل."""
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Trust Scan Report", ln=True, align="C")
    pdf.ln(4)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"Type: {scan_type}", ln=True)
    pdf.cell(0, 8, f"Target: {target}", ln=True)
    pdf.cell(0, 8, f"Final status: {final_status}", ln=True)
    pdf.cell(0, 8, f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(6)

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
        with st.spinner("🔎 Scanning Google Safe Browsing..."):
            response = rq.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_google}",
                json=data,
                timeout=20
            )
        result = response.json()
        if "matches" in result:
            st.error("⚠ Google: Dangerous")
            return "Dangerous"
        else:
            st.success("✔ Google: Safe")
            return "Safe"
    except Exception as e:
        st.error(f"Google scan failed: {e}")
        return "Error"

def scan_vt(URL):
    """فحص URL باستخدام VirusTotal (يحاول تقرير مسبقًا ثم فحص جديد إذا لازم)"""
    tables = []
    is_dangerous = False
    try:
        with vt.Client(API_KEY_virustotal) as client:
            try:
                url_obj = client.get_url_report(URL)
            except Exception:
                with st.spinner("🛡️ VirusTotal is scanning the URL (may take some seconds)..."):
                    url_obj = client.scan_url(URL, wait_for_completion=True)

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

            # عرض مختصر سريع في واجهة المستخدم (تفصيل كامل سيظهر لاحقًا)
            st.table(pd.DataFrame(tables))

            if is_dangerous:
                st.error("⚠ VirusTotal engines: Some engines flagged this URL")
            else:
                st.success("✔ VirusTotal engines: No engine flagged this URL")

            return ("Dangerous" if is_dangerous else "Safe"), tables

    except Exception as e:
        st.error(f"VirusTotal scan failed: {e}")
        return "Error", tables

# ----------------------------- واجهة المستخدم -----------------------------
st.title("🛡️ Trust Scan — URL & File Security Scanner")
st.write("افحص روابطك أو ملفاتك بسرعة، واحفظ تقرير PDF شامل يحتوي على Google Safe Browsing وVirusTotal.")

tab1, tab2 = st.tabs(["🔗 Scan URL", "📁 Scan File"])

# ----------------------------- تبويب URL -----------------------------
with tab1:
    col_a, col_b = st.columns([3,1])
    with col_a:
        URL = st.text_input("أدخل الرابط الذي تريد فحصه (http:// أو https://):")
        choose = st.radio(
            "اختر نوع الفحص:",
            ["🛡️ VirusTotal Scan", "🔍 Google Safe Browsing Scan", "Both (Deep Scan)"]
        )
    with col_b:
        st.markdown("**Quick tips:**")
        st.markdown("- استخدم `Both (Deep Scan)` للحصول على تقرير شامل.")
        st.markdown("- انتظر انتهاء الفحص قبل تحميل التقرير.")

    start_button = st.button("Start Scanning", disabled=st.session_state.is_scanning)

    if start_button:
        if not URL:
            st.warning("❌ Please enter a URL before scanning.")
        elif not (URL.startswith("https://") or URL.startswith("http://")):
            st.error("Enter a valid URL (http:// or https://)")
        else:
            # تجنّب ضغط متعدد
            st.session_state.is_scanning = True
            try:
                status_g = status_v = None
                vt_tables = []

                if choose == "🛡️ VirusTotal Scan":
                    status_v, vt_tables = scan_vt(URL)

                elif choose == "🔍 Google Safe Browsing Scan":
                    status_g = scan_g(URL)

                elif choose == "Both (Deep Scan)":
                    col1, col2 = st.columns(2)
                    with col1:
                        st.subheader("🔍 Google Safe Browsing")
                        status_g = scan_g(URL)
                    with col2:
                        st.subheader("🛡️ VirusTotal")
                        status_v, vt_tables = scan_vt(URL)

                    if status_g != status_v and status_g not in ("Error", None) and status_v not in ("Error", None):
                        st.warning("⚠ Discrepancy: Google and VirusTotal disagree — be cautious.")

                # تحديد الحالة النهائية
                if status_v == "Dangerous" or status_g == "Dangerous":
                    final_status = "Dangerous"
                elif status_v == "Error" or status_g == "Error":
                    final_status = "Error"
                else:
                    final_status = "Safe"

                # دمج النتائج: نعرض Google أولًا ثم نتائج VirusTotal
                combined = []
                if status_g:
                    combined.append({"engine": "Google Safe Browsing", "Category": status_g, "status": status_g.lower()})
                if vt_tables:
                    combined.extend(vt_tables)

                # عرض ملخص جميل
                st.markdown("### 📋 Unified Results")
                if combined:
                    df = pd.DataFrame(combined)
                    st.dataframe(df)
                else:
                    st.info("No detailed results to show.")

                # توليد زر تنزيل PDF إذا في نتائج أو على الأقل نتيجة Google
                if combined:
                    if choose == "Both (Deep Scan)":
                        scan_label = "Deep Scan (Google + VirusTotal)"
                    elif choose == "🛡️ VirusTotal Scan":
                        scan_label = "URL Scan (VirusTotal)"
                    else:
                        scan_label = "URL Scan (Google Safe Browsing)"

                    pdf_bytes = generate_pdf_bytes(URL, scan_label, final_status, combined)
                    file_name = f"trustscan_{scan_label.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

                    st.download_button(
                        label="📄 Download PDF report",
                        data=pdf_bytes,
                        file_name=file_name,
                        mime="application/pdf"
                    )

                    # حفظ في سجل الجلسة
                    st.session_state.history.insert(0, {
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": scan_label,
                        "target": URL,
                        "final_status": final_status,
                        "table": combined,
                        "pdf_bytes": pdf_bytes,
                        "file_name": file_name
                    })

            finally:
                st.session_state.is_scanning = False  # تأكد نعيد التفعيل

# ----------------------------- تبويب الملفات -----------------------------
with tab2:
    st.title("📁 Scan Your File")
    uploaded_file = st.file_uploader("Choose your file:", type=None)
    max_file_mb = 30
    if uploaded_file:
        size_mb = uploaded_file.size / (1024 * 1024)
        st.write(f"File size: {size_mb:.2f} MB")
        if size_mb > max_file_mb:
            st.error(f"❌ The file is too big. Maximum allowed size is {max_file_mb} MB")
        else:
            file_scan_btn = st.button("Start File Scanning", disabled=st.session_state.is_scanning)
            if file_scan_btn:
                st.session_state.is_scanning = True
                try:
                    with vt.Client(API_KEY_virustotal) as client:
                        with st.spinner("🛡️ VirusTotal is scanning the file..."):
                            analysis = client.scan_file(uploaded_file, wait_for_completion=True)

                    stats = getattr(analysis, "stats", {}) or {}
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)
                    harmless = stats.get("harmless", 0)

                    summary_row = {
                        "engine": "VirusTotal summary",
                        "Category": f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}",
                        "status": "dangerous" if (malicious > 0 or suspicious > 0) else "safe"
                    }
                    st.table(pd.DataFrame([summary_row]))

                    if malicious > 0:
                        st.error("⚠ It's a malicious file")
                    elif suspicious > 0:
                        st.warning("⚠ It's a suspicious file")
                    else:
                        st.success("✔ It seems safe")

                    pdf_bytes = generate_pdf_bytes(uploaded_file.name, "File Scan (VirusTotal)", summary_row["status"], [summary_row])
                    file_name = f"trustscan_file_{uploaded_file.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                    st.download_button(
                        label="📄 Download PDF report",
                        data=pdf_bytes,
                        file_name=file_name,
                        mime="application/pdf"
                    )

                    st.session_state.history.insert(0, {
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "File Scan (VirusTotal)",
                        "target": uploaded_file.name,
                        "final_status": summary_row["status"],
                        "table": [summary_row],
                        "pdf_bytes": pdf_bytes,
                        "file_name": file_name
                    })

                except Exception as e:
                    st.error(f"File scan failed: {e}")
                finally:
                    st.session_state.is_scanning = False

# ----------------------------- سجل الفحوصات (History) -----------------------------
st.markdown("---")
st.header("🕘 Scan History (this session)")
if st.session_state.history:
    for i, item in enumerate(st.session_state.history):
        with st.expander(f"{item['time']} — {item['type']} — {item['target']} — {item['final_status']}", expanded=(i==0)):
            st.write(f"**Target:** {item['target']}")
            st.write(f"**Type:** {item['type']}")
            st.write(f"**Final status:** {item['final_status']}")
            st.table(pd.DataFrame(item["table"]))
            st.download_button(
                label="📄 Download this report PDF",
                data=item["pdf_bytes"],
                file_name=item["file_name"],
                mime="application/pdf"
            )
else:
    st.info("No scans done in this session yet.")
