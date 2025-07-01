import streamlit as st
import requests

def scan(url):
    try:
        r = requests.get(url, headers={"Origin": "http://evil.com"}, timeout=5)
        if "Access-Control-Allow-Origin" in r.headers and "evil.com" in r.headers.get("Access-Control-Allow-Origin", ""):
            st.error("[CORS] Misconfigured: Wildcard or Evil Origin Allowed")
        else:
            st.success("[CORS] Configuration looks fine")
    except Exception as e:
        st.warning(f"[CORS] Error: {str(e)}")