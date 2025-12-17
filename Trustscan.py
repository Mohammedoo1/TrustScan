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

danger_words = [
    "malicious", "phishing", "malware", "trojan",
    "harmful", "suspicious", "spam", "dangerous"
]

# ----------------------------- PDF -----------------------------
def generate_pdf(target, scan_type, final_status, table_data):
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

    pdf.set_font("Arial", "B", 11)
    pdf.cell(50, 8, "Engine", 1)
    pdf.cell(110, 8, "Category", 1)
    pdf.cell(30, 8, "Status", 1, ln=True)

    pdf.set_font("Arial", size=10)

    for row in table_data:
        y_before = pdf.get_y()
        pdf.cell(50, 8, row["engine"], 1)

        x = pdf.get_x()
        y = pdf.get_y()
        pdf.multi_cell(110, 8, row["Category"], 1)

        y_after = pdf.get_y()
        pdf.set_xy(x + 110, y)
        pdf.cell(30, y_after - y, row["status"], 1)
        pdf.set_y(y_after)

    return pdf.output(dest="S").encode("latin-1")

# ----------------------------- Google -----------------------------
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
        with st.spinner("Scanning Google Safe Browsing..."):
            r = rq.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY_google}",
                json=data,
                timeout=20
            )
        return "Dangerous" if "matches" in r.json() else "Safe"
    except:
        return "Error"

# ----------------------------- VirusTotal URL -----------------------------
def scan_vt(URL):
    tables = []
    is_dangerous = False

    with vt.Client(API_KEY_virustotal) as client:
        try:
            url_obj = client.get_url_report(URL)
        except:
            with st.spinner("🛡️ VirusTotal is scanning the URL..."):
                url_obj = client.scan_url(URL, wait_for_completion=True)

        results = getattr(url_obj, "last_analysis_results", {})

        for engine, details in results.items():
            category = details.get("category", "undetected").lower()
            status = "dangerous" if any(w in category for w in danger_words) else "safe"
            if status == "dangerous":
                is_dangerous = True

            tables.append({
                "engine": engine,
                "Category": category,
                "status": status
            })

    st.table(tables)
    return ("Dangerous" if is_dangerous else "Safe"), tables

# ----------------------------- URL TAB -----------------------------
with tab1:
    st.title("Scan URL")
    URL = st.text_input("Enter your URL:")

    choose = st.radio(
        "Choose scan:",
        ["VirusTotal", "Google", "Both"]
    )

    if st.button("Start Scanning"):
        tables = []
        status_g = status_v = None

        if choose == "VirusTotal":
            status_v, tables = scan_vt(URL)
            final_status = status_v
            scan_type = "URL Scan (VirusTotal)"

        elif choose == "Google":
            status_g = scan_g(URL)
            tables = [{
                "engine": "Google Safe Browsing",
                "Category": status_g,
                "status": status_g.lower()
            }]
            final_status = status_g
            scan_type = "URL Scan (Google)"

        else:
            status_g = scan_g(URL)
            status_v, vt_tables = scan_vt(URL)

            tables = [{
                "engine": "Google Safe Browsing",
                "Category": status_g,
                "status": status_g.lower()
            }] + vt_tables

            final_status = "Dangerous" if "Dangerous" in [status_g, status_v] else "Safe"
            scan_type = "URL Scan (Google + VirusTotal)"

        pdf = generate_pdf(URL, scan_type, final_status, tables)
        st.download_button("📄 Download PDF", pdf, "url_scan.pdf", "application/pdf")

# ----------------------------- FILE TAB (المعدل) -----------------------------
with tab2:
    st.title("Scan Your File")
    uploaded_file = st.file_uploader("Choose file:")

    if uploaded_file and st.button("Start File Scanning"):
        tables = []
        is_dangerous = False

        with vt.Client(API_KEY_virustotal) as client:
            with st.spinner("🛡️ VirusTotal is scanning the file..."):
                analysis = client.scan_file(uploaded_file, wait_for_completion=True)

        results = getattr(analysis, "results", {})

        for engine, details in results.items():
            category = details.get("category", "undetected").lower()
            status = "dangerous" if category in ["malicious", "suspicious"] else "safe"

            if status == "dangerous":
                is_dangerous = True

            tables.append({
                "engine": engine,
                "Category": category,
                "status": status
            })

        st.table(tables)

        final_status = "Dangerous" if is_dangerous else "Safe"
        pdf = generate_pdf(
            uploaded_file.name,
            "File Scan (VirusTotal)",
            final_status,
            tables
        )

        st.download_button(
            "📄 Download PDF report",
            pdf,
            "file_scan.pdf",
            "application/pdf"
        )
