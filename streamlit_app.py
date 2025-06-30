import streamlit as st import requests from urllib.parse import urlencode

st.set_page_config(page_title="Advanced Vulnerability Scanner", layout="wide") st.title("🛡️ Advanced Web Vulnerability Tester")

target_url = st.text_input("Enter the target URL:", "http://example.com")

st.markdown("### Select Vulnerabilities to Test") test_sqli = st.checkbox("SQL Injection") test_xss = st.checkbox("Cross-Site Scripting (XSS)") test_redirect = st.checkbox("Open Redirect") test_ssti = st.checkbox("Server-Side Template Injection (SSTI)") enable_fingerprint = st.checkbox("→ Fingerprint Template Engine (SSTI)") test_ddos = st.checkbox("DDoS Simulation (safe test)") test_headers = st.checkbox("Security Headers Check")

def test_sql_injection(url): payloads = ["' OR '1'='1", "1 OR 1=1", "1' --"] for payload in payloads: test_url = f"{url}?id={payload}" try: r = requests.get(test_url, timeout=5) if any(err in r.text.lower() for err in ["sql", "syntax", "warning"]): return True, test_url except Exception: pass return False, url

def test_xss_vulnerability(url): payloads = [ "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg onload=alert(1)>" ] for payload in payloads: test_url = f"{url}?q={payload}" try: r = requests.get(test_url, timeout=5) if payload in r.text: return True, test_url except Exception: pass return False, url

def test_open_redirect(url): redirect_url = "https://evil.com" for param in ["next", "url", "redirect"]: test_url = f"{url}?{param}={redirect_url}" try: r = requests.get(test_url, allow_redirects=False, timeout=5) if r.status_code in [301, 302] and redirect_url in r.headers.get("Location", ""): return True, test_url except Exception: pass return False, url

def test_ssti_vulnerability(url, fingerprint=False): payloads = { "{{77}}": ("49", "Jinja2"), "{{7'7'}}": ("7777777", "Jinja2"), "${77}": ("49", "Velocity/Freemarker"), "<%= 77 %>": ("49", "ERB"), "#set($a=7*7) $a": ("49", "Velocity") } for payload, (expected, engine) in payloads.items(): test_url = f"{url}?input={payload}" try: r = requests.get(test_url, timeout=5) if expected in r.text: if fingerprint: return True, test_url, engine return True, test_url, None except Exception: continue return False, url, None

def simulate_ddos(url): try: for _ in range(10): requests.get(url, timeout=1) return "Simulated 10 quick requests to observe server response (safe)." except Exception as e: return f"Error during simulation: {e}"

def check_security_headers(url): try: r = requests.get(url, timeout=5) missing = [] recommended = [ "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy" ] for h in recommended: if h not in r.headers: missing.append(h) if missing: return False, missing return True, [] except Exception as e: return False, [str(e)]

if st.button("Run Tests"): st.markdown("## 🔍 Results")

if test_sqli:
    result, link = test_sql_injection(target_url)
    st.write("**SQL Injection:**", "✅ Vulnerable" if result else "❌ Not vulnerable", link)

if test_xss:
    result, link = test_xss_vulnerability(target_url)
    st.write("**XSS:**", "✅ Vulnerable" if result else "❌ Not vulnerable", link)

if test_redirect:
    result, link = test_open_redirect(target_url)
    st.write("**Open Redirect:**", "✅ Vulnerable" if result else "❌ Not vulnerable", link)

if test_ssti:
    result, link, engine = test_ssti_vulnerability(target_url, enable_fingerprint)
    if result:
        st.write("**SSTI:** ✅ Vulnerable", link)
        if enable_fingerprint:
            st.write(f"→ Likely Template Engine: **{engine}**")
    else:
        st.write("**SSTI:** ❌ Not vulnerable", link)

if test_ddos:
    st.write("**DDoS Simulation:**", simulate_ddos(target_url))

if test_headers:
    good, result = check_security_headers(target_url)
    if good:
        st.success("✅ All recommended security headers present.")
    else:
        st.warning("⚠️ Missing headers:")
        for h in result:
            st.text(f"- {h}")

