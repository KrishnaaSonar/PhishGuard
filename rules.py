# rules.py
# PhishGuard - Detection Rules Engine
# Contains all keyword lists and pattern rules used to detect phishing indicators

# -----------------------------------------------------------
# URGENCY KEYWORDS - Language meant to pressure the user
# -----------------------------------------------------------
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "limited time",
    "verify now", "account suspended", "expires soon",
    "last chance", "final notice", "response required",
    "action required", "don't delay", "time sensitive"
]

# -----------------------------------------------------------
# THREAT LANGUAGE - Language that implies consequences
# -----------------------------------------------------------
THREAT_KEYWORDS = [
    "blocked", "terminated", "locked", "expired",
    "warning", "security alert", "unauthorized access",
    "unusual activity", "suspicious login", "access denied",
    "will be closed", "permanently disabled", "legal action"
]

# -----------------------------------------------------------
# CREDENTIAL HARVESTING - Language trying to steal login info
# -----------------------------------------------------------
CREDENTIAL_KEYWORDS = [
    "enter password", "login now", "confirm credentials",
    "verify account", "update payment", "confirm your identity",
    "re-enter", "validate your", "submit your details",
    "click here to login", "sign in to confirm"
]

# -----------------------------------------------------------
# FINANCIAL KEYWORDS - Money-related phishing triggers
# -----------------------------------------------------------
FINANCIAL_KEYWORDS = [
    "bank account", "credit card", "wire transfer",
    "payment required", "invoice attached", "refund pending",
    "transaction failed", "billing information", "unpaid balance",
    "winning prize", "lottery", "claim your reward"
]

# -----------------------------------------------------------
# SUSPICIOUS LINK PATTERNS - URLs that may be malicious
# -----------------------------------------------------------
SUSPICIOUS_LINK_PATTERNS = [
    r"http://",             # Non-secure HTTP
    r"bit\.ly",            # URL shortener
    r"tinyurl\.com",       # URL shortener
    r"t\.co",              # Twitter shortener (often misused)
    r"goo\.gl",            # Google shortener (deprecated, still used)
    r"ow\.ly",             # Hootsuite shortener
    r"rb\.gy",             # Shortener
    r"cutt\.ly",           # Shortener
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Raw IP address links
]

# -----------------------------------------------------------
# FAKE LOGIN LANGUAGE - Impersonation patterns
# -----------------------------------------------------------
FAKE_LOGIN_KEYWORDS = [
    "paypal", "amazon", "apple id", "google account",
    "microsoft account", "bank of america", "chase bank",
    "netflix", "instagram login", "facebook security",
    "your account has been", "dear customer", "dear user",
    "dear valued member"
]

# -----------------------------------------------------------
# FORMATTING ANOMALIES - Detection via regex patterns
# -----------------------------------------------------------
# These are applied using regex in detector.py

EXCESS_CAPS_THRESHOLD = 5       # Number of ALL-CAPS words to trigger flag
EXCLAMATION_THRESHOLD = 2       # Number of '!' to trigger flag
REPEATED_SYMBOL_THRESHOLD = 3  # Same symbol repeated 3+ times in a row