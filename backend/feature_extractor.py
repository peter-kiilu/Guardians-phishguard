"""
PhishGuard — Feature Extractor
================================
Extracts lexical features from a URL for phishing detection.

This module produces the same feature set used during training
(aligned with the Kaggle 'Web Page Phishing Detection' dataset columns).
"""

import re
import math
from urllib.parse import urlparse


# Suspicious keywords commonly found in phishing URLs
PHISH_HINTS = [
    "login", "verify", "secure", "bank", "update", "account",
    "confirm", "signin", "submit", "password", "credential",
    "suspend", "restrict", "alert", "billing", "pay",
]

# Suspicious TLDs commonly abused for phishing
SUSPICIOUS_TLDS = [
    "ru", "tk", "xyz", "top", "pw", "ga", "ml", "cf", "gq",
    "buzz", "work", "click", "link", "info", "online", "site",
]

# Known URL shortening services
SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
]


def extract_features(url):
    """
    Extracts a dictionary of lexical features from a URL.
    Feature names match the Kaggle dataset columns used during training.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url.lower()

    # ── Length features ──
    length_url = len(url)
    length_hostname = len(hostname)

    # ── Count features ──
    nb_dots = url.count(".")
    nb_hyphens = url.count("-")
    nb_at = url.count("@")
    nb_qm = url.count("?")
    nb_and = url.count("&")
    nb_eq = url.count("=")
    nb_underscore = url.count("_")
    nb_slash = url.count("/")
    nb_www = url.lower().count("www")
    nb_com = url.lower().count("com")
    nb_dslash = url.count("//")

    # ── IP address detection ──
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    ip = 1 if re.search(ip_pattern, hostname) else 0

    # ── Protocol features ──
    http_in_path = 1 if "http" in path.lower() else 0
    https_token = 1 if parsed.scheme == "https" else 0

    # ── Ratio of digits ──
    ratio_digits_url = sum(c.isdigit() for c in url) / max(len(url), 1)
    ratio_digits_host = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)

    # ── Punycode detection (internationalized domain) ──
    punycode = 1 if hostname.startswith("xn--") or "xn--" in hostname else 0

    # ── Port presence ──
    port = 1 if parsed.port else 0

    # ── TLD analysis ──
    host_parts = hostname.split(".")
    tld = host_parts[-1] if host_parts else ""

    tld_in_path = 1 if any(f".{t}" in path.lower() for t in ["com", "org", "net", "edu", "gov"]) else 0
    tld_in_subdomain = 1 if any(f".{t}." in hostname for t in ["com", "org", "net"]) else 0

    # ── Subdomain analysis ──
    nb_subdomains = max(0, len(host_parts) - 2) if len(host_parts) > 2 else 0
    abnormal_subdomain = 1 if nb_subdomains > 2 else 0

    # ── Prefix/suffix (hyphen in domain) ──
    # Domain is the second-to-last part (before TLD)
    domain = host_parts[-2] if len(host_parts) >= 2 else hostname
    prefix_suffix = 1 if "-" in domain else 0

    # ── URL shortening service ──
    shortening_service = 1 if any(s in hostname for s in SHORTENING_SERVICES) else 0

    # ── Redirections (count of // after protocol) ──
    url_after_protocol = url.split("//", 1)[-1] if "//" in url else url
    nb_redirection = url_after_protocol.count("//")
    nb_external_redirection = nb_redirection  # Simplified for URL-only analysis

    # ── Word-level features ──
    words_raw = re.split(r"[^a-zA-Z]", url)
    words_raw = [w for w in words_raw if w]  # Remove empty strings
    words_host = re.split(r"[^a-zA-Z]", hostname)
    words_host = [w for w in words_host if w]
    words_path = re.split(r"[^a-zA-Z]", path)
    words_path = [w for w in words_path if w]

    length_words_raw = len(words_raw)
    longest_word_host = max((len(w) for w in words_host), default=0)
    longest_word_path = max((len(w) for w in words_path), default=0)
    avg_words_raw = sum(len(w) for w in words_raw) / max(len(words_raw), 1)
    avg_word_host = sum(len(w) for w in words_host) / max(len(words_host), 1)
    avg_word_path = sum(len(w) for w in words_path) / max(len(words_path), 1)

    # ── Character repetition ──
    char_repeat = _max_char_repeat(url)

    # ── Phishing hints (suspicious keywords) ──
    phish_hints = sum(1 for word in PHISH_HINTS if word in full_url)

    # ── Suspicious TLD ──
    suspecious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # ── Statistical report (placeholder — would need WHOIS/external API) ──
    statistical_report = 0

    return {
        "length_url": length_url,
        "length_hostname": length_hostname,
        "ip": ip,
        "nb_dots": nb_dots,
        "nb_hyphens": nb_hyphens,
        "nb_at": nb_at,
        "nb_qm": nb_qm,
        "nb_and": nb_and,
        "nb_eq": nb_eq,
        "nb_underscore": nb_underscore,
        "nb_slash": nb_slash,
        "nb_www": nb_www,
        "nb_com": nb_com,
        "nb_dslash": nb_dslash,
        "http_in_path": http_in_path,
        "https_token": https_token,
        "ratio_digits_url": ratio_digits_url,
        "ratio_digits_host": ratio_digits_host,
        "punycode": punycode,
        "port": port,
        "tld_in_path": tld_in_path,
        "tld_in_subdomain": tld_in_subdomain,
        "abnormal_subdomain": abnormal_subdomain,
        "nb_subdomains": nb_subdomains,
        "prefix_suffix": prefix_suffix,
        "shortening_service": shortening_service,
        "nb_redirection": nb_redirection,
        "nb_external_redirection": nb_external_redirection,
        "length_words_raw": length_words_raw,
        "char_repeat": char_repeat,
        "longest_word_host": longest_word_host,
        "longest_word_path": longest_word_path,
        "avg_words_raw": avg_words_raw,
        "avg_word_host": avg_word_host,
        "avg_word_path": avg_word_path,
        "phish_hints": phish_hints,
        "suspecious_tld": suspecious_tld,
        "statistical_report": statistical_report,
    }


def get_feature_vector(url):
    """Returns a list of feature values (in training order) for ML model input."""
    features = extract_features(url)
    # Return values in the same order as SELECTED_FEATURES in train_model.py
    return list(features.values())


def _max_char_repeat(s):
    """Returns the max consecutive repetition count of any character."""
    if not s:
        return 0
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1
    return max_repeat
