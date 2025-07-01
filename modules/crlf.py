import streamlit as st
import requests

def scan(url):
    try:
        payload = "%0d%0aInjected-Header: test"
        r = requests.get(f"{url}?q={payload}", timeout=5)
        if "Injected-Header" in r.text:
            st.error("[CRLF] Injection Detected")
        else:
            st.success("[CRLF] Not Found")
    except Exception as e:
        st.warning(f"[CRLF] Error: {str(e)}")