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
    try:

        analysis = client.scan_url(URL)
        st.write(f"scanned {analysis} ")
        while True:
            result = client.get_object(f"/analyses/{analysis.id}")
            if result.status == "completed":
                break


        st.write("Scan completed!")
        for engine, details in result.results.items():
            results= details['category'].lower()


            for word in danger_words: 
                if word in results:    
                    st.write("it is dangerous")


    except Exception as e:
         st.write(e)

if st.button("Click me to start scanning"):
    scan(URL)


