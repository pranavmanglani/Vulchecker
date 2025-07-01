import streamlit as st
from sslyze import (
    Scanner,
    ServerNetworkLocationViaDirectConnection,
    ServerScanRequest,
    ServerScanResult,
)
from sslyze.errors import ConnectionToServerFailed


def scan(url):
    st.subheader("🔐 Cipher Suite Scanner")

    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        port = 443  # default HTTPS port

        st.write(f"Target Host: `{host}:{port}`")

        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(host, port)
        scanner = Scanner()
        request = ServerScanRequest(server_location=server_location, scan_commands={"tls_1_2_cipher_suites", "tls_1_3_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites", "tls_1_1_cipher_suites"})

        scanner.queue_scan(request)
        result: ServerScanResult = next(scanner.get_results())

        for command_result in result.scan_result.supported_cipher_suites:
            suites = result.scan_result.supported_cipher_suites[command_result]
            if suites:
                st.markdown(f"### 🧪 {command_result.name}")
                for suite in suites:
                    cipher_name = suite.cipher_suite.name
                    strength = "✅ Secure"
                    if any(w in cipher_name.lower() for w in ["rc4", "3des", "null", "md5", "export"]):
                        strength = "❌ Insecure"
                    elif "sha1" in cipher_name.lower():
                        strength = "⚠️ Weak"
                    st.write(f"- {cipher_name} → **{strength}**")
            else:
                st.info(f"No supported ciphers for {command_result.name}")

    except ConnectionToServerFailed:
        st.error("❌ Failed to connect to the server. Make sure it's using HTTPS.")
    except Exception as e:
        st.error(f"[Cipher] Error: {e}")
