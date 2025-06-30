import streamlit as st
import requests
import re
import json
from urllib.parse import urlparse, parse_qs

st.title("Passive Web Vulnerability Scanner")

# Input: one or more URLs (one per line)
urls_input = st.text_area("Enter one or more URLs (one per line):")
if st.button("Scan"):
    if not urls_input.strip():
        st.warning("Please enter at least one URL.")
    else:
        # Prepare results list
        scan_results = []
        urls = [u.strip() for u in urls_input.splitlines() if u.strip()]
        for url in urls:
            issues = []
            st.write(f"Scanning **{url}**...")
            parsed = urlparse(url)
            query = parsed.query.lower()

            # --- 1. SQL Injection patterns ---
            # Look for typical SQLi payloads (e.g. ' OR 1=1 --).
            if re.search(r"('|\")\s*or\s*1\s*=\s*1", query, re.IGNORECASE) or re.search(r"('|\")\s*1\s*=\s*1", query, re.IGNORECASE):
                issues.append("Possible SQL injection pattern found (e.g. \"' OR 1=1\").")
            if "--" in query or "%27--" in query or "%27%20--" in query:
                issues.append("SQL comment sequence detected (`--`), could indicate SQL injection attempt.")
            if "union" in query and "select" in query:
                issues.append("Presence of 'UNION SELECT' pattern (common in SQL injection).")

            # --- 2. XSS patterns ---
            # Check for <script> tags or inline event handlers in query params.
            if "<script" in query or "&lt;script" in query:
                issues.append("HTML <script> tag found in URL (possible XSS).")
            if "onload=" in query or "onerror=" in query or "onclick=" in query:
                issues.append("Inline event handler (e.g. onclick=) found in URL (possible XSS).")
            if "javascript:" in query:
                issues.append("Javascript URI scheme found in URL (possible XSS).")

            # --- 3. Open Redirect patterns ---
            # Check for redirect-like parameters pointing to an external domain.
            redirect_params = ["redirect", "url", "next", "target", "dest", "goto"]
            for param, values in parse_qs(query).items():
                if param in redirect_params:
                    for val in values:
                        # Parse the redirect target
                        val = val.strip()
                        if val:
                            target = urlparse(val if val.startswith("http") else val)
                            # Consider cases like //evil.com or full http(s) URLs
                            if target.netloc and target.netloc != parsed.netloc:
                                issues.append(f"Parameter `{param}` redirects to external domain `{target.netloc}` (open-redirect).")
                            elif val.startswith("//"):
                                # Protocol-relative URL
                                ext_domain = val.split("//",1)[1].split("/",1)[0]
                                if ext_domain and ext_domain != parsed.netloc:
                                    issues.append(f"Parameter `{param}` has protocol-relative URL to `{ext_domain}` (open-redirect).")

            # --- 4. SSTI patterns ---
            # Look for template injection markers like {{...}}, ${...}, <%...%>.
            if re.search(r"\{\{.*\}\}", query):
                issues.append("Template expression `{{…}}` found (possible SSTI).")
            if re.search(r"\$\{.*\}", query):
                issues.append("Template expression `${…}` found (possible SSTI).")
            if re.search(r"<%.*%>", query):
                issues.append("Template expression `<%…%>` found (possible SSTI).")

            # --- 5. Rate-limiting headers ---
            try:
                resp = requests.get(url, timeout=10)
                headers = resp.headers
                # Check for standard rate-limit headers
                has_retry = "Retry-After" in headers
                has_rl_remaining = any(h.lower() == "x-ratelimit-remaining" for h in headers)
                if not has_retry and not has_rl_remaining:
                    issues.append("No rate-limit headers (e.g. Retry-After, X-RateLimit-Remaining) found in response.")
                else:
                    if not has_retry:
                        issues.append("`Retry-After` header missing (no guidance on when to retry).")
                    if not has_rl_remaining:
                        issues.append("`X-RateLimit-Remaining` header missing (no info on remaining requests).")
            except Exception as e:
                issues.append(f"Could not fetch URL ({e}).")

            # Show results for this URL
            if issues:
                with st.expander(f"Issues for {url}"):
                    st.markdown("\n".join(f"- {issue}" for issue in issues))
            else:
                with st.expander(f"Issues for {url}"):
                    st.success("No issues detected.")

            # Append to JSON results
            scan_results.append({"url": url, "issues": issues})

        # Output JSON and download button
        st.subheader("Scan Results (JSON)")
        st.json(scan_results)
        json_data = json.dumps(scan_results, indent=2)
        st.download_button(label="Download JSON", data=json_data, file_name="scan_results.json", mime="application/json")