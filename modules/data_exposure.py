import streamlit as st
import requests

def scan(url):
    endpoints = [".env", "config.php", ".git/config"]
    found = False
    for ep in endpoints:
        try:
            r = requests.get(f"{url.rstrip('/')}/{ep}", timeout=5)
            if r.status_code == 200 and "password" in r.text.lower():
                st.error(f"[Sensitive Data Exposure] Found: {url}/{ep}")
                found = True
        except Exception:
            pass
    if not found:
        st.success("[Sensitive Data Exposure] Not Found")