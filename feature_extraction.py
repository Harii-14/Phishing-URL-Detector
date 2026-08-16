import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}

    # 1. Length of URL
    features['url_length'] = len(url)

    # 2. Presence of '@' symbol (phishing trick)
    features['has_at_symbol'] = 1 if '@' in url else 0

    # 3. Presence of '-' in domain (phishing sites often use this)
    features['has_hyphen'] = 1 if '-' in urlparse(url).netloc else 0

    # 4. Number of dots (too many dots = suspicious)
    features['dot_count'] = url.count('.')

    # 5. HTTPS present or not
    features['has_https'] = 1 if urlparse(url).scheme == 'https' else 0

    # 6. IP address instead of domain name (major red flag)
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0

    # 7. Number of special characters
    features['special_char_count'] = len(re.findall(r'[@\-_?=&%]', url))

    # 8. URL contains suspicious keywords
    suspicious_words = ['login', 'verify', 'account', 'update', 'secure', 'banking']
    features['has_suspicious_word'] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    return features


# Test the function with example URLs
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login-verify-account",
        "https://secure-bank-update.com/account@login"
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        result = extract_features(url)
        for key, value in result.items():
            print(f"  {key}: {value}")