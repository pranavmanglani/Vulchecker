import streamlit as st

def scan(url):
    test_paths = ["/admin", "/user/delete?id=1", "/config"]
    st.warning("[Broken Access Control] Test manually for restricted resources:")
    for path in test_paths:
        st.write(f"🔸 Try accessing: {url.rstrip('/')}{path}")