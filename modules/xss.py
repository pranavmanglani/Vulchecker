
import streamlit as st
import requests

def scan(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"
    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            st.error(f"[XSS] Vulnerability Found: {test_url}")
        else:
            st.success("[XSS] Not Found")
    except Exception as e:
        st.warning(f"[XSS] Error: {str(e)}")
