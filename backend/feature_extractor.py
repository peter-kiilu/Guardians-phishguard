import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ['login', 'verify', 'secure', 'bank', 'update', 'account', 'banking', 'confirm']

def extract_features(url):
    """
    Extracts lexical features from a URL for phishing detection.
    Returns a dictionary of features.
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ''
    path = parsed_url.path or ''
    
    # 1. URL Length
    url_length = len(url)
    
    # 2. Number of dots
    num_dots = url.count('.')
    
    # 3. Number of hyphens
    num_hyphens = url.count('-')
    
    # 4. Presence of @
    at_symbol = 1 if '@' in url else 0
    
    # 5. Presence of IP address in hostname
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    has_ip = 1 if re.search(ip_pattern, hostname) else 0
    
    # 6. HTTPS usage
    is_https = 1 if parsed_url.scheme == 'https' else 0
    
    # 7. Count suspicious words
    suspicious_count = sum(1 for word in SUSPICIOUS_WORDS if word in url.lower())
    
    # 8. Number of subdomains
    # Subtracting 2 (domain + TLD) if there are more than 2 parts
    host_parts = hostname.split('.')
    num_subdomains = max(0, len(host_parts) - 2) if len(host_parts) > 2 else 0

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "at_symbol": at_symbol,
        "has_ip": has_ip,
        "is_https": is_https,
        "suspicious_count": suspicious_count,
        "num_subdomains": num_subdomains
    }

def get_feature_vector(url):
    """Returns a list of feature values for ML model input."""
    features = extract_features(url)
    return [
        features["url_length"],
        features["num_dots"],
        features["num_hyphens"],
        features["at_symbol"],
        features["has_ip"],
        features["is_https"],
        features["suspicious_count"],
        features["num_subdomains"]
    ]
