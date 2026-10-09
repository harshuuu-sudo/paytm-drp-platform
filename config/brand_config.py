"""
Brand Profile & Whitelist Engine Configuration for Paytm (One97 Communications Ltd.)
Principal Cybersecurity Engineering Standard - Digital Risk Protection Platform
"""

from typing import Dict, List, Set

# Anchor Brand Identity
BRAND_NAME: str = "Paytm"
PARENT_COMPANY: str = "One97 Communications Ltd."
BRAND_STEM: str = "paytm"

# Registered Canonical Names & Variations
CANONICAL_BRAND_NAMES: List[str] = [
    "Paytm",
    "Paytm Money",
    "Paytm Care",
    "Paytm Payments Bank",
    "Paytm Insider",
    "Paytm Business",
    "Paytm Soundbox",
    "One97 Communications",
    "One97 Communications Ltd.",
]

# Strict Whitelist: Official Social Media Handles (All platforms, case-insensitive)
OFFICIAL_HANDLES: Set[str] = {
    "@paytm",
    "@paytmcare",
    "@paytmmoney",
    "@paytmbank",
    "@paytminsider",
    "@paytmbusiness",
    "@paytm_business",
    "@one97",
    "paytm",
    "paytmcare",
    "paytmmoney",
    "paytmbank",
    "paytminsider",
    "paytmbusiness",
    "one97",
}

# Strict Whitelist: Official Mobile App Store Package / Bundle Identifiers
OFFICIAL_PACKAGE_IDS: Set[str] = {
    "net.one97.paytm",
    "com.paytm.business",
    "com.paytmmoney",
    "com.paytm.pos",
    "net.one97.paytm.insider",
}

# Strict Whitelist: Authorized Mobile App Store Publisher Names
OFFICIAL_PUBLISHERS: Set[str] = {
    "paytm - one97 communications ltd.",
    "one97 communications limited",
    "one97 communications ltd",
    "one97 communications ltd.",
    "paytm payments bank limited",
    "paytm money limited",
    "one97",
}

# Strict Whitelist: Official Brand Domains
OFFICIAL_DOMAINS: Set[str] = {
    "paytm.com",
    "paytmmoney.com",
    "paytmbank.com",
    "one97.com",
    "insider.in",
}

# High-Risk Brand Hijacking Padding Tokens (frequently abused in financial phishing)
HIGH_RISK_PADDING_TOKENS: Set[str] = {
    "care",
    "refund",
    "support",
    "helpdesk",
    "helpline",
    "tollfree",
    "service",
    "customer",
    "customercare",
    "upi",
    "kyc",
    "wallet",
    "cashback",
    "fastag",
    "loan",
    "instantloan",
    "agent",
    "executive",
    "official",
    "verify",
    "unblock",
    "desk",
    "portal",
    "resolution",
    "dispute",
}

# Phishing / Scam Content Triggers (Social Media Bios, App descriptions, etc.)
SCAM_CONTENT_TRIGGERS: List[Dict[str, str]] = [
    {"pattern": r"urgent\s+refund", "label": "Urgent Refund Phishing", "weight": 25},
    {"pattern": r"dm\s+(for|to)\s+(stuck\s+)?(upi|refund|money)", "label": "Unauthorized Direct Message Phishing", "weight": 30},
    {"pattern": r"stuck\s+upi(\s+issue|\s+refund)?", "label": "Stuck UPI Social Engineering", "weight": 25},
    {"pattern": r"kyc\s*(update|verification|expire|mandatory|suspend)", "label": "KYC Expiration Trap", "weight": 25},
    {"pattern": r"airdrop|free\s+cashback|bonus\s+claimed|free\s+money", "label": "Financial Lure / Airdrop Scam", "weight": 20},
    {"pattern": r"call\s+(now|urgently|\+?91[\s\-]?[6-9]\d{9}|1800)", "label": "Fake Support Helpline / Vishing Hook", "weight": 20},
    {"pattern": r"(unblock|suspended)\s+(wallet|account|fastag)", "label": "Account Block Panic Vector", "weight": 25},
    {"pattern": r"whatsapp\s+(helpline|support|number|chat)", "label": "Out-of-Band Exfiltration (WhatsApp)", "weight": 20},
    {"pattern": r"t\.me/|telegram\s+channel", "label": "Malicious Telegram Redirection", "weight": 20},
    {"pattern": r"send\s+(otp|pin|cvv|password)", "label": "Credential Harvesting", "weight": 35},
    {"pattern": r"fast\s+loan|instant\s+disbursal|guaranteed\s+loan", "label": "Predatory Loan Impersonation", "weight": 20},
]

# Leetspeak Substitution Mapping
LEETSPEAK_MAP: Dict[str, str] = {
    "0": "o",
    "4": "a",
    "1": "l",
    "$": "s",
    "@": "a",
    "3": "e",
    "5": "s",
    "7": "t",
    "8": "b",
    "!": "i",
    "+": "t",
    "|": "l",
}

# Unicode Homoglyph Mapping (Cyrillic, Greek, Latin Lookalikes)
UNICODE_HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic small lookalikes
    "\u0430": "a",  # Cyrillic small 'а'
    "\u0441": "c",  # Cyrillic small 'с'
    "\u0435": "e",  # Cyrillic small 'е'
    "\u043e": "o",  # Cyrillic small 'о'
    "\u0440": "p",  # Cyrillic small 'р'
    "\u0445": "x",  # Cyrillic small 'х'
    "\u0443": "y",  # Cyrillic small 'у'
    "\u0456": "i",  # Cyrillic small 'і'
    "\u0458": "j",  # Cyrillic small 'ј'
    "\u0455": "s",  # Cyrillic small 'ѕ'
    "\u0442": "t",  # Cyrillic small 'т'
    "\u043c": "m",  # Cyrillic small 'м'
    "\u0432": "b",  # Cyrillic small 'в'
    "\u043a": "k",  # Cyrillic small 'к'
    "\u043d": "h",  # Cyrillic small 'н'
    # Cyrillic capital lookalikes
    "\u0410": "a",
    "\u0412": "b",
    "\u0415": "e",
    "\u041a": "k",
    "\u041c": "m",
    "\u041d": "h",
    "\u041e": "o",
    "\u0420": "p",
    "\u0421": "c",
    "\u0422": "t",
    "\u0423": "y",
    "\u0425": "x",
    # Greek lookalikes
    "\u03b1": "a",  # alpha
    "\u03b2": "b",  # beta
    "\u03b5": "e",  # epsilon
    "\u03b9": "i",  # iota
    "\u03ba": "k",  # kappa
    "\u03bd": "v",  # nu
    "\u03bf": "o",  # omicron
    "\u03c1": "p",  # rho
    "\u03c4": "t",  # tau
    "\u03c5": "u",  # upsilon
    "\u03c7": "x",  # chi
    # Latin diacritics / variants
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u",
    "ý": "y", "ÿ": "y",
}

# Risk Tier Thresholds
RISK_TIERS = {
    "CRITICAL": 85.0,  # >= 85%
    "HIGH": 60.0,      # >= 60%
    "MEDIUM": 30.0,    # >= 30%
    "SAFE": 0.0,       # < 30% (or strictly 0% if OFFICIAL_SAFE)
}
