import streamlit as st
import vt

API = "f201bfdb4e779f527e33ef7c05749409292f1976fcfa59899a3383cb02f00754"

st.title("welcome in  Scan URL ")

URL = st.text_input("enter your URl :")

client = vt.Client(API)

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

def scan(URL):
    tables= []
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
                is_dangerous=True
                
            else:
                tables.append({"engine": engine, "Category": results, "status": "safe"})

        if is_dangerous:
            st.error("dangerous")
        else:
            st.success("safe")    
        st.table(tables)
    except Exception as e:
         st.write(e)

if st.button("Click me to start scanning"):
    scan(URL)



