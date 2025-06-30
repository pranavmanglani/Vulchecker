import streamlit as st
import requests
from urllib.parse import urljoin, urlencode

st.set_page_config(page_title="Vulnerability Tester", layout="wide")

st.title("🛡️ Web Vulnerability Tester")
target_url = st.text_input("Enter the target URL:", "http://example.com")

st.markdown("### Select Vulnerabilities to Test")
test_sqli = st.checkbox("SQL Injection")
test_xss = st.checkbox("Cross-Site Scripting (XSS)")
test_redirect = st.checkbox("Open Redirect")
test_ssti = st.checkbox("Server-Side Template Injection (SSTI)")
test_ddos = st.checkbox("DDoS Simulation (DoS only, safe method)")

headers = {"User-Agent": "Security-Scanner/1.0"}

def test_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    try:
        response = requests.get(test_url, headers=headers, timeout=5)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            return True, test_url
    except Exception:
        pass
    return False, test_url

def test_xss_vulnerability(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"
    try:
        response = requests.get(test_url, headers=headers, timeout=5)
        if payload in response.text:
            return True, test_url
    except Exception:
        pass
    return False, test_url

def test_open_redirect(url):
    redirect_url = "https://evil.com"
    payload = urlencode({"next": redirect_url})
    test_url = f"{url}?{payload}"
    try:
        response = requests.get(test_url, headers=headers, allow_redirects=False, timeout=5)
        if response.status_code in [301, 302] and "Location" in response.headers:
            if redirect_url in response.headers["Location"]:
                return True, test_url
    except Exception:
        pass
    return False, test_url

def test_ssti_vulnerability(url):
    payload = "{{7*7}}"
    test_url = f"{url}?name={payload}"
    try:
        response = requests.get(test_url, headers=headers, timeout=5)
        if "49" in response.text:
            return True, test_url
    except Exception:
        pass
    return False, test_url

def simulate_ddos(url):
    try:
        for _ in range(10):  # Simulate 10 quick requests
            requests.get(url, headers=headers, timeout=1)
        return "Simulated 10 requests to check server stability (no real DDoS)."
    except Exception as e:
        return f"Error during simulation: {e}"

if st.button("Run Tests"):
    st.markdown("## 🔍 Results")
    if test_sqli:
        vulnerable, test_url = test_sql_injection(target_url)
        st.write("**SQL Injection:**", "✅ Vulnerable" if vulnerable else "❌ Not vulnerable", test_url)
    if test_xss:
        vulnerable, test_url = test_xss_vulnerability(target_url)
        st.write("**XSS:**", "✅ Vulnerable" if vulnerable else "❌ Not vulnerable", test_url)
    if test_redirect:
        vulnerable, test_url = test_open_redirect(target_url)
        st.write("**Open Redirect:**", "✅ Vulnerable" if vulnerable else "❌ Not vulnerable", test_url)
    if test_ssti:
        vulnerable, test_url = test_ssti_vulnerability(target_url)
        st.write("**SSTI:**", "✅ Vulnerable" if vulnerable else "❌ Not vulnerable", test_url)
    if test_ddos:
        st.write("**DDoS Simulation:**", simulate_ddos(target_url))