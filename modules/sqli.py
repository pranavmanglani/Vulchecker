import streamlit as st
import requests

def scan(url):
    payloads = ["' OR '1'='1", "'--", "' OR 1=1 --"]
    found = False
    for payload in payloads:
        try:
            test_url = f"{url}?id={payload}"
            r = requests.get(test_url, timeout=5)
            if any(x in r.text.lower() for x in ["sql", "syntax", "mysql", "error"]):
                st.error(f"[SQL Injection] Vulnerability found: {test_url}")
                found = True
                break
        except Exception as e:
            st.warning(f"[SQLI] Error: {str(e)}")
    if not found:
        st.success("[SQL Injection] Not Found")