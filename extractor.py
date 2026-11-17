import math
import re
from urllib.parse import urlsplit

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "digit_to_length_ratio", "hostname_to_url_ratio",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_question_marks", "num_ampersands", "num_at_symbols", "num_percent_encodings",
    "has_https", "has_ip_address", "is_shortened_url", "has_non_standard_port",
    "subdomain_count", "is_suspicious_tld",
    "digit_count", "letter_count", "suspicious_keyword_count", "url_entropy"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "tk", "ml", "ga", "cf", "gq",
    "buzz", "club", "work", "click", "link", "info", "online", "site"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "bank",
    "signin", "confirm", "wallet", "password", "paypal", "ebay", "webscr", "cmd"
]

IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 6)


def extract_features(url: str) -> list:
    url = str(url).strip()
    url_lower = url.lower()

    parse_target = url if "://" in url else f"http://{url}"
    try:
        parsed = urlsplit(parse_target)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
    except ValueError:
        hostname, path, query, port = "", url, "", None

    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    digit_count = sum(c.isdigit() for c in url)
    letter_count = sum(c.isalpha() for c in url)

    digit_to_length_ratio = round(digit_count / url_length, 6) if url_length > 0 else 0.0
    hostname_to_url_ratio = round(hostname_length / url_length, 6) if url_length > 0 else 0.0

    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_question_marks = url.count("?")
    num_ampersands = url.count("&")
    num_at_symbols = url.count("@")
    num_percent_encodings = url.count("%")

    has_https = 1 if url_lower.startswith("https://") else 0
    has_ip_address = 1 if (IPV4_PATTERN.match(hostname) or ":" in hostname) else 0

    clean_host = hostname[4:] if hostname.startswith("www.") else hostname
    is_shortened_url = 1 if clean_host in SHORTENERS else 0
    has_non_standard_port = 1 if (port is not None and port not in (80, 443)) else 0

    host_parts = [p for p in hostname.split(".") if p]
    subdomain_count = max(0, len(host_parts) - 2) if (hostname and not has_ip_address) else 0
    tld = host_parts[-1] if len(host_parts) >= 2 and not has_ip_address else ""
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    suspicious_keyword_count = sum(url_lower.count(kw) for kw in SUSPICIOUS_KEYWORDS)
    url_entropy = calculate_entropy(url)

    return [
        url_length, hostname_length, path_length, query_length,
        digit_to_length_ratio, hostname_to_url_ratio,
        num_dots, num_hyphens, num_underscores, num_slashes,
        num_question_marks, num_ampersands, num_at_symbols, num_percent_encodings,
        has_https, has_ip_address, is_shortened_url, has_non_standard_port,
        subdomain_count, is_suspicious_tld,
        digit_count, letter_count, suspicious_keyword_count, url_entropy
    ]
