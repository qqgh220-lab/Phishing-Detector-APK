import re
import urllib.parse
import requests
import streamlit as st

st.set_page_config(
    page_title="Phishing URL Detector", page_icon="🛡️", layout="centered"
)


def unshorten_url(url):
    if not url.startswith(("http://", "https://")):
        target = "http://" + url
    else:
        target = url

    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.head(
            target, allow_redirects=True, timeout=4, headers=headers
        )
        return response.url
    except Exception:
        return url


def analyze_url(original_url):
    score = 0
    reasons = []

    final_url = unshorten_url(original_url)
    was_redirected = original_url.strip() != final_url.strip()

    parsed = urllib.parse.urlparse(final_url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    domain_only = domain.split(":")[0]

    if not final_url.startswith("https://"):
        score += 1
        reasons.append((
            "Missing HTTPS Encryption",
            "URL does not use secure HTTPS protocol.",
            "High",
        ))

    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain_only):
        score += 2
        reasons.append((
            "Direct IP Address Usage",
            "Uses raw IP address instead of domain name.",
            "Critical",
        ))

    if "@" in final_url:
        score += 2
        reasons.append((
            "Contains '@' Symbol",
            "Obfuscates actual destination.",
            "Critical",
        ))

    if len(final_url) > 75:
        score += 1
        reasons.append((
            "Abnormal Length",
            f"URL length ({len(final_url)} chars) exceeds 75 limit.",
            "Medium",
        ))

    if domain_only.count("-") > 2:
        score += 1
        reasons.append((
            "Excessive Hyphens",
            f"Domain contains {domain_only.count('-')} hyphens.",
            "Medium",
        ))

    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd"]
    if any(s in original_url.lower() for s in shorteners) or was_redirected:
        score += 2
        reasons.append((
            "URL Shortener / Redirection Detected",
            f"Concealed destination unmasked -> Resolved to: {final_url}",
            "High",
        ))

    status = (
        "SAFE" if score == 0 else ("SUSPICIOUS" if score <= 2 else "PHISHING")
    )
    return status, score, reasons, final_url, was_redirected


st.title("🛡️ Phishing URL Detection System")
st.caption("Advanced Real-time Redirection & Heuristic Analysis")

target_url = st.text_input("Enter Target URL:")

if st.button("Analyze URL", type="primary"):
    if target_url:
        with st.spinner("Unmasking URL & Analyzing..."):
            status, score, reasons, final_url, was_redirected = analyze_url(
                target_url
            )

        if was_redirected:
            st.info(f"🔗 **Unmasked Target Destination:** `{final_url}`")

        if status == "SAFE":
            st.success(f"Result: **{status}** (Risk Score: {score})")
        elif status == "SUSPICIOUS":
            st.warning(f"Result: **{status}** (Risk Score: {score})")
        else:
            st.error(f"Result: **{status}** (Risk Score: {score})")

        for title, desc, severity in reasons:
            st.markdown(f"- **{title}** [{severity}]: {desc}")
        
