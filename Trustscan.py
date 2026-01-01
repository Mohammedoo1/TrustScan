from datetime import datetime
import streamlit as st
import vt
import requests as rq
from fpdf import FPDF

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
    tables = []
    is_dangerous = False
    try:
        with vt.Client(API_KEY_virustotal) as client:
            try:
                url_obj = client.get_url_report(URL)
            except Exception:
                
                with st.spinner("🛡️ VirusTotal is scanning the URL..."):
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


            if is_dangerous:
                st.error("⚠ Dangerous (VirusTotal engines)")
            else:
                st.success("✔ Safe (VirusTotal engines)")
                
            st.table(tables)

            return "Dangerous" if is_dangerous else "Safe", tables

    except Exception as e:
        st.error(f"VirusTotal scan failed: {e}")
        return "Error", tables


with tab1:
    st.title("Scan URL 🌐")
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

    
        pdf_tables = []
        final_status = "Safe"
        scan_type = ""

        if choose == "🛡️ VirusTotal Scan":
            pdf_tables = tables
            final_status = status_v
            scan_type = "URL Scan (VirusTotal)"

        elif choose == "🔍 Google Safe Browsing Scan":
            pdf_tables = [{
                "engine": "Google Safe Browsing",
                "Category": status_g,
                "status": (status_g or "error").lower()
            }]
            final_status = status_g
            scan_type = "URL Scan (Google Safe Browsing)"

        elif choose == "Both (Deep Scan)":
    
            pdf_tables = [{
                "engine": "Google Safe Browsing",
                "Category": status_g,
                "status": (status_g or "error").lower()
            }]
            if tables:
                pdf_tables += tables

            
            if status_g == "Dangerous" or status_v == "Dangerous":
                final_status = "Dangerous"
            elif status_g == "Error" or status_v == "Error":
                
                final_status = "Error"
            else:
                final_status = "Safe"

            scan_type = "URL Scan (Google + VirusTotal)"

        
        if pdf_tables:
            pdf_bytes = generate_pdf(
                URL,
                scan_type,
                final_status or "Error",
                pdf_tables
            )
            st.download_button(
                label="📄 Download PDF report",
                data=pdf_bytes,
                file_name=f"trustscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )

with tab2:
    st.title("Scan File 📁")
    max_file = 30  
    uploaded_file = st.file_uploader("Choose your file:", type=None)

    if uploaded_file:
        size = uploaded_file.size / (1024 * 1024)
        st.write(f"File size: {size:.2f} MB")

        if size > max_file:
            st.error(f"❌ The file is too big. Maximum allowed size is {max_file} MB")

        elif st.button("Start File Scanning"):
            try:
                tables = []
                is_dangerous = False

                with vt.Client(API_KEY_virustotal) as client:
                    with st.spinner("🛡️ VirusTotal is scanning the file..."):
                        analysis = client.scan_file(
                            uploaded_file,
                            wait_for_completion=True
                        )

                results = getattr(analysis, "results", {})

                for engine, details in results.items():
                    try:
                        category = details.get("category", "undetected").lower()
                    except Exception:
                        category = str(details).lower()

                    status = (
                        "dangerous"
                        if any(w in category for w in danger_words)
                        else "safe"
                    )

                    if status == "dangerous":
                        is_dangerous = True

                    tables.append({
                        "engine": engine,
                        "Category": category,
                        "status": status
                    })

                
                if not tables:
                    tables.append({
                        "engine": "VirusTotal",
                        "Category": "No engine details available",
                        "status": "safe"
                    })

            

                if is_dangerous:
                    st.error("⚠ Dangerous file detected")
                else:
                    st.success("✔ File seems safe")
                    
                st.table(tables)

                
                pdf_bytes = generate_pdf(
                    uploaded_file.name,
                    "File Scan (VirusTotal)",
                    "Dangerous" if is_dangerous else "Safe",
                    tables
                )

                st.download_button(
                    label="📄 Download PDF report",
                    data=pdf_bytes,
                    file_name=f"trustscan_file_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )

            except Exception as e:
                st.error(f"File scan failed: {e}")




