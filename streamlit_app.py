import streamlit as st
from modules import bac, crlf, cipher, components, cors, data_exposure, xss, traversal, deserialization, sqli, ddos, lfi

st.title("🛡️ Ultimate Vulnerability Scanner")
target = st.text_input("Enter target URL (e.g., http://example.com)")

if st.button("Run Scan"):
    if target:
        st.info(f"Scanning {target}...")
        with st.spinner("Running all tests..."):
            bac.scan(target)
            crlf.scan(target)
            cipher.scan(target)
            components.scan(target)
            cors.scan(target)
            data_exposure.scan(target)
            xss.scan(target)
            traversal.scan(target)
            deserialization.scan(target)
            sqli.scan(target)
            ddos.scan(target)
            lfi.scan(target)
        st.success("✅ Scan complete.")
    else:
        st.warning("Please enter a valid URL.")
