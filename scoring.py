# scoring.py
# PhishGuard - Risk Scoring System
# Calculates total risk score based on detected flags and maps to risk level

# -----------------------------------------------------------
# SCORE WEIGHTS - How many points each issue adds
# -----------------------------------------------------------
SCORE_WEIGHTS = {
    "suspicious_link": 3,       # Links are serious indicators
    "urgency": 2,               # Urgency language
    "threat": 2,                # Threat/consequence language
    "credential_request": 3,    # Asking for login/passwords
    "financial": 2,             # Money-related phishing
    "fake_login": 2,            # Impersonating brands
    "excess_caps": 1,           # ALL CAPS formatting
    "exclamation_marks": 1,     # Multiple exclamation marks
    "repeated_symbols": 1,      # Repeated suspicious symbols
}

# -----------------------------------------------------------
# RISK LEVELS - Score ranges map to risk categories
# -----------------------------------------------------------
RISK_LEVELS = [
    (0, 2, "SAFE",    "✅ This email appears safe. No significant threats detected."),
    (3, 5, "MEDIUM",  "⚠️ Moderate risk. Review this email carefully before taking action."),
    (6, 99, "HIGH",   "🚨 High risk! This email shows multiple phishing indicators. Do NOT click any links."),
]

def calculate_risk(flags: dict) -> tuple:
    """
    Takes a dictionary of detected flags and their counts.
    Returns (total_score, risk_level_string, suggested_action)
    """
    total_score = 0

    # Add points for each detected flag category
    for flag_key, flag_count in flags.items():
        if flag_key in SCORE_WEIGHTS and flag_count > 0:
            total_score += SCORE_WEIGHTS[flag_key]

    # Determine risk level based on score
    for min_score, max_score, level, action in RISK_LEVELS:
        if min_score <= total_score <= max_score:
            return total_score, level, action

    # Fallback (should not reach here)
    return total_score, "UNKNOWN", "Unable to determine risk level."