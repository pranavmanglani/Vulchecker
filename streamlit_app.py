import streamlit as st
import requests
from urllib.parse import urlparse, parse_qs

st.title("Passive Web Vulnerability Scanner")

# Input: multiline text area for URLs
urls_input = st.text_area("Enter URL(s) (one per line):")
if st.button("Start Scan"):
    # Iterate each URL provided
    for url in urls_input.splitlines():
        url = url.strip()
        if not url:
            continue
        # Attempt to fetch the page (passive GET)
        try:
            resp = requests.get(url, timeout=5)  # No payload injection
        except Exception as e:
            st.error(f"Cannot fetch {url}: {e}")
            continue

        issues = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Check parameters for SQLi and XSS patterns
        for name, values in params.items():
            for value in values:
                val_lower = value.lower()
                # SQL Injection heuristics
                if any(marker in val_lower for marker in [" or ", "'or ", "%27or ", "1=1", "--", "union", "select", "drop"]):
                    issues.append(f"⚠ SQLi-like pattern in `{name}`: `{value}`")
                # XSS heuristics (common HTML/JS fragments)
                if any(x in val_lower for x in ["<script", "<img", "javascript:", "onerror", "alert("]):
                    issues.append(f"⚠ Possible XSS in `{name}`: `{value}`")
                # SSTI heuristics
                if "{{" in value or "${" in value:
                    issues.append(f"⚠ Possible SSTI in `{name}`: `{value}`")
                # Open Redirect heuristics
                if name.lower() in ["redirect", "redirecturl", "url", "next", "dest", "destination"]:
                    dest = value
                    dest_parsed = urlparse(dest)
                    # If the parameter is an absolute URL and not same domain
                    if dest_parsed.scheme in ("http","https") and dest_parsed.netloc:
                        if dest_parsed.netloc != parsed.netloc:
                            issues.append(f"⚠ Open-redirect param `{name}` → `{dest}`")

        # Check for missing rate-limit headers
        headers = resp.headers
        # Known rate-limit headers (e.g. Okta: X-Rate-Limit-*6)
        rate_headers = ["Retry-After", "X-RateLimit-Remaining", "X-Rate-Limit-Remaining", "X-RateLimit-Limit"]
        if not any(h in headers for h in rate_headers):
            issues.append("⚠ No rate-limit headers (e.g. `Retry-After`, `X-RateLimit-Remaining`) found")

        # Display results in an expander per URL
        with st.expander(f"Results for {url}"):
            if issues:
                for item in issues:
                    st.write(f"- {item}")
            else:
                st.write("- No obvious issues detected.")

        # Prepare data for export
        result = {"url": url, "issues": issues}
        st.download_button(
            "Export JSON",
            data=str(result),
            file_name=f"scan_{url.replace('://','_').replace('/','_')}.json",
            mime="application/json"
        )