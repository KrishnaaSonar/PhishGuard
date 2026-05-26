# detector.py
# PhishGuard - Core Detection Engine
# Runs the email content through all rule sets and returns findings

import re
from rules import (
    URGENCY_KEYWORDS,
    THREAT_KEYWORDS,
    CREDENTIAL_KEYWORDS,
    FINANCIAL_KEYWORDS,
    SUSPICIOUS_LINK_PATTERNS,
    FAKE_LOGIN_KEYWORDS,
    EXCESS_CAPS_THRESHOLD,
    EXCLAMATION_THRESHOLD,
    REPEATED_SYMBOL_THRESHOLD
)
from scoring import calculate_risk


def analyze_email(email_text: str) -> dict:
    """
    Main function to analyze email text for phishing indicators.
    Returns a complete result dictionary.
    """

    # Normalize text for keyword matching (lowercase copy)
    lower_text = email_text.lower()

    # Store all detected flags and their details
    flags = {}
    details = []

    # ----------------------------------------------------------
    # 1. CHECK URGENCY KEYWORDS
    # ----------------------------------------------------------
    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in lower_text]
    if urgency_hits:
        flags["urgency"] = len(urgency_hits)
        details.append(f"⚠ Urgency language detected: {', '.join(urgency_hits[:3])}")

    # ----------------------------------------------------------
    # 2. CHECK THREAT LANGUAGE
    # ----------------------------------------------------------
    threat_hits = [kw for kw in THREAT_KEYWORDS if kw in lower_text]
    if threat_hits:
        flags["threat"] = len(threat_hits)
        details.append(f"⚠ Threat language found: {', '.join(threat_hits[:3])}")

    # ----------------------------------------------------------
    # 3. CHECK CREDENTIAL HARVESTING
    # ----------------------------------------------------------
    cred_hits = [kw for kw in CREDENTIAL_KEYWORDS if kw in lower_text]
    if cred_hits:
        flags["credential_request"] = len(cred_hits)
        details.append(f"🔑 Credential request detected: {', '.join(cred_hits[:3])}")

    # ----------------------------------------------------------
    # 4. CHECK FINANCIAL KEYWORDS
    # ----------------------------------------------------------
    fin_hits = [kw for kw in FINANCIAL_KEYWORDS if kw in lower_text]
    if fin_hits:
        flags["financial"] = len(fin_hits)
        details.append(f"💰 Financial keyword found: {', '.join(fin_hits[:3])}")

    # ----------------------------------------------------------
    # 5. CHECK FAKE LOGIN / IMPERSONATION LANGUAGE
    # ----------------------------------------------------------
    fake_hits = [kw for kw in FAKE_LOGIN_KEYWORDS if kw in lower_text]
    if fake_hits:
        flags["fake_login"] = len(fake_hits)
        details.append(f"🎭 Brand impersonation detected: {', '.join(fake_hits[:3])}")

    # ----------------------------------------------------------
    # 6. CHECK SUSPICIOUS LINKS / URLs
    # ----------------------------------------------------------
    url_hits = []
    for pattern in SUSPICIOUS_LINK_PATTERNS:
        matches = re.findall(pattern, email_text)
        if matches:
            url_hits.extend(matches)

    if url_hits:
        flags["suspicious_link"] = len(url_hits)
        details.append(f"🔗 Suspicious link/URL pattern found ({len(url_hits)} instance(s))")

    # ----------------------------------------------------------
    # 7. CHECK FORMATTING - EXCESS CAPS
    # ----------------------------------------------------------
    # Count words that are fully uppercase and at least 3 chars long
    caps_words = re.findall(r'\b[A-Z]{3,}\b', email_text)
    if len(caps_words) >= EXCESS_CAPS_THRESHOLD:
        flags["excess_caps"] = len(caps_words)
        details.append(f"🔠 Excessive capitalization detected ({len(caps_words)} uppercase words)")

    # ----------------------------------------------------------
    # 8. CHECK FORMATTING - MULTIPLE EXCLAMATION MARKS
    # ----------------------------------------------------------
    exclamation_count = email_text.count('!')
    if exclamation_count >= EXCLAMATION_THRESHOLD:
        flags["exclamation_marks"] = exclamation_count
        details.append(f"❗ Multiple exclamation marks found ({exclamation_count})")

    # ----------------------------------------------------------
    # 9. CHECK FORMATTING - REPEATED SYMBOLS
    # ----------------------------------------------------------
    # Look for patterns like *****, ....., ######, etc.
    repeated_symbols = re.findall(r'([^a-zA-Z0-9\s])\1{' + str(REPEATED_SYMBOL_THRESHOLD - 1) + r',}', email_text)
    if repeated_symbols:
        flags["repeated_symbols"] = len(repeated_symbols)
        details.append(f"🔁 Repeated symbols detected ({len(repeated_symbols)} instance(s))")

    # ----------------------------------------------------------
    # CALCULATE RISK SCORE
    # ----------------------------------------------------------
    score, risk_level, suggested_action = calculate_risk(flags)

    # ----------------------------------------------------------
    # RETURN COMPLETE RESULT
    # ----------------------------------------------------------
    return {
        "risk_level": risk_level,
        "score": score,
        "max_score": 10,  # Reference max for display purposes
        "flags": flags,
        "details": details,
        "suggested_action": suggested_action,
        "flag_count": len(flags)
    }