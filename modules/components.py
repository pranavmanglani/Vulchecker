import streamlit as st
import requests

def scan(url):
    try:
        r = requests.get(url, timeout=5)
        server = r.headers.get("Server", "Unknown")
        if server != "Unknown":
            st.warning(f"[Components] Server header found: {server} (check for known vulnerabilities)")
        else:
            st.success("[Components] No exposed server version")
    except Exception as e:
        st.warning(f"[Components] Error: {str(e)}")