import streamlit as st
import vt
import requests as rq

tab1,tab2 = st.tabs(["  Scan URL  ", "  Scan Fill "])

API_KEY = st.secrets["API_google"]
API = st.secrets["API_virus"]

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
            analysis = client.scan_url(URL)

            with st.spinner("Scanning..."):
                while True:
                    result = client.get_object(f"/analyses/{analysis.id}")
                    if result.status == "completed":
                        break

            st.write("Scan completed!")
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
                return "dangerous"
            else:
                st.success("safe")
                return "safe" , tables

        except Exception as e:
            st.write(e)


    if "vt_result" not in st.session_state:
        st.session_state.vt_result = None

    choose = st.radio(
        "choose where you want to check your link :",
        ["🛡️ VirusTotal Scan", "🔍 Google Safe Browsing Scan", "Both (for deep scan)"]
    )

    if st.button("start scanning"):
        if not URL:
            st.warning("❌ Please enter a URL before scanning.")
            st.stop()
        else:
            st.session_state.vt_result = scan(URL)

        if choose == "🛡️ VirusTotal Scan":
            if st.session_state.vt_result:
                status, tables_result = st.session_state.vt_result
                if st.button("Click me if you want to see the deatiles"):
                    st.table(tables_result)

        elif choose == "🔍 Google Safe Browsing Scan":
            scan_g(URL)

        elif choose == "Both (for deep scan)":
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("🔍 Google Safe Browsing")
                status_g = scan_g(URL)
            with col2:
                st.subheader("🛡️ VirusTotal Scan")
                status_v ,_ = scan(URL)
            if status_g != status_v:
                st.warning("⚠ Maybe it is risky, don't open it ")

with tab2:
 #     def showrtn_link():
#         st.title("short URL ")
 #        uRL = st.text_input("enter URL:")
#
 #        try:
  #           if st.button("show the real link"):
#
 #                URl_info=rq.get(uRL)
  #               st.write(URl_info.url)
   #      except Exception as e:
    #         st.write(e)

    st.title("Scan your File")
    max_file=30
    uploaded_file = st.file_uploader("Choose ypur file :", type=None)
    if uploaded_file is not None:
        size= uploaded_file.size / (1024*1024)
        if size > max_file:
            st.error("the file size is too big")
        else:
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
            st.info("I am not ensure about the file")


