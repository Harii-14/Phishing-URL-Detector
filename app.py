from flask import Flask, render_template, request
import joblib
import re
import sqlite3
import whois
import difflib
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

model = joblib.load("phishing_model.pkl")
feature_columns = joblib.load("feature_columns.pkl")

DB_FILE = "history.db"

POPULAR_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'paypal.com', 'apple.com',
    'microsoft.com', 'netflix.com', 'instagram.com', 'flipkart.com', 'myntra.com',
    'whatsapp.com', 'linkedin.com', 'twitter.com', 'youtube.com', 'gmail.com',
    'hdfcbank.com', 'sbi.co.in', 'icicibank.com', 'axisbank.com', 'irctc.co.in',
    'zomato.com', 'swiggy.com', 'ola.com', 'uber.com', 'phonepe.com', 'paytm.com',
    'github.com', 'wikipedia.org', 'yahoo.com', 'ebay.com', 'dropbox.com',
    'adobe.com', 'outlook.com', 'office.com', 'icloud.com',
    'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
    'binance.com', 'coinbase.com', 'wazirx.com', 'zerodha.com', 'upstox.com',
    'airbnb.com', 'booking.com', 'makemytrip.com', 'goibibo.com',
    'reliancejio.com', 'jiomart.com', 'bigbasket.com', 'nykaa.com',
    'indianrail.gov.in', 'incometax.gov.in', 'uidai.gov.in', 'epfindia.gov.in',
    'discord.com', 'telegram.org', 'snapchat.com', 'tiktok.com', 'spotify.com',
]

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'signin', 'banking', 'security']


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            confidence REAL NOT NULL,
            checked_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_to_history(url, result, confidence):
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT INTO history (url, result, confidence, checked_at) VALUES (?, ?, ?, ?)",
        (url, result, confidence, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def get_recent_history(limit=8):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT url, result, confidence, checked_at FROM history ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return rows


def check_urlhaus(url):
    """Check the URL against URLhaus, a live global malware/phishing blocklist.
    Catches known-malicious URLs even on old, previously-trustworthy (hacked) domains."""
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=4
        )
        data = resp.json()
        if data.get("query_status") == "ok":
            threat = data.get("threat", "malicious URL")
            return f"This exact URL is listed on URLhaus as a known {threat}"
        return None
    except Exception:
        return None


def check_suspicious_domain(domain):
    domain_lower = domain.lower().replace('www.', '')

    if domain_lower in POPULAR_DOMAINS:
        return None

    for popular in POPULAR_DOMAINS:
        similarity = difflib.SequenceMatcher(None, domain_lower, popular).ratio()
        if similarity >= 0.75:
            return f"Domain closely resembles '{popular}' (possible typosquatting)"

    has_keyword = any(word in domain_lower for word in SUSPICIOUS_KEYWORDS)
    if has_keyword and '-' in domain_lower:
        return "Domain combines a sensitive keyword (login/verify/secure/etc.) with a hyphenated structure"

    return None


def check_whois(domain):
    try:
        w = whois.whois(domain)
        is_registered = bool(w.domain_name) or bool(w.registrar) or bool(w.org)

        if not is_registered:
            return -1, -1, False

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return 0, 1, True

        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        age_days = (datetime.now() - creation_date).days
        age_months = age_days / 30
        age_score = 1 if age_months >= 6 else -1
        return age_score, 1, True
    except Exception:
        return -1, -1, False


def check_page_content(url, domain):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}
        resp = requests.get(url, headers=headers, timeout=5, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")

        has_password_field = bool(soup.find("input", {"type": "password"}))

        page_text = soup.get_text().lower()
        title = (soup.title.string if soup.title else "").lower()

        mentioned_brand = None
        for brand_domain in POPULAR_DOMAINS:
            brand_name = brand_domain.split('.')[0]
            if len(brand_name) > 3 and (brand_name in title or page_text.count(brand_name) >= 3):
                if brand_domain not in domain.lower():
                    mentioned_brand = brand_name
                    break

        forms = soup.find_all("form")
        external_form_action = False
        for form in forms:
            action = form.get("action", "")
            if action.startswith("http") and domain not in action:
                external_form_action = True
                break

        if has_password_field and mentioned_brand:
            return f"Page has a login form and repeatedly mentions '{mentioned_brand}', but is not hosted on the official {mentioned_brand} domain"

        if has_password_field and external_form_action:
            return "Login form on this page submits data to a different, external domain"

        return None
    except Exception:
        return None


def extract_url_features(url):
    features = {}
    domain = urlparse(url).netloc
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    is_ip = bool(re.search(ip_pattern, url))

    features['having_IPhaving_IP_Address'] = -1 if is_ip else 1
    features['URLURL_Length'] = -1 if len(url) >= 75 else (0 if len(url) >= 54 else 1)
    features['Shortining_Service'] = -1 if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']) else 1
    features['having_At_Symbol'] = -1 if '@' in url else 1
    features['double_slash_redirecting'] = -1 if url.rfind('//') > 7 else 1
    features['Prefix_Suffix'] = -1 if '-' in domain else 1
    features['having_Sub_Domain'] = -1 if domain.count('.') > 2 else 1
    features['HTTPS_token'] = 1 if urlparse(url).scheme == 'https' else -1

    whois_found = True
    if not is_ip and domain:
        age_score, dns_score, whois_found = check_whois(domain)
        features['age_of_domain'] = age_score
        features['DNSRecord'] = dns_score
    else:
        features['age_of_domain'] = -1
        features['DNSRecord'] = -1
        whois_found = False

    return features, is_ip, whois_found


def get_top_reasons(features_dict, top_n=3):
    importances = model.feature_importances_
    scored = []
    for i, col in enumerate(feature_columns):
        val = features_dict[col]
        if val == -1:
            scored.append((importances[i], col))
    scored.sort(reverse=True)
    return [name for _, name in scored[:top_n]]


FRIENDLY_NAMES = {
    'having_IPhaving_IP_Address': 'Uses an IP address instead of a domain name',
    'URLURL_Length': 'URL is unusually long',
    'Shortining_Service': 'Uses a URL shortening service',
    'having_At_Symbol': "Contains an '@' symbol",
    'double_slash_redirecting': 'Suspicious redirect pattern in URL',
    'Prefix_Suffix': "Domain contains a '-' (hyphen)",
    'having_Sub_Domain': 'Too many sub-domains',
    'HTTPS_token': 'Not using HTTPS',
    'age_of_domain': 'Domain is very new or age could not be verified',
    'DNSRecord': 'No valid DNS/WHOIS record found for this domain',
}


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    confidence = None
    reasons = []
    submitted_url = ""

    if request.method == "POST":
        url = request.form["url"].strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        submitted_url = url
        domain = urlparse(url).netloc

        blocklist_reason = check_urlhaus(url)
        suspicion_reason = check_suspicious_domain(domain)
        features_dict, is_ip, whois_found = extract_url_features(url)

        if blocklist_reason:
            result = "Phishing"
            confidence = 99.0
            reasons = [blocklist_reason]

        elif suspicion_reason:
            result = "Phishing"
            confidence = 94.0
            reasons = [suspicion_reason]

        elif is_ip:
            result = "Phishing"
            confidence = 96.0
            reasons = ["Uses an IP address instead of a domain name"]

        elif not whois_found:
            result = "Phishing"
            confidence = 92.0
            reasons = ["This domain does not appear to be registered (no WHOIS record found)"]

        else:
            feature_values = [features_dict[col] for col in feature_columns]
            prediction = model.predict([feature_values])[0]
            probabilities = model.predict_proba([feature_values])[0]
            result = "Legitimate" if prediction == 1 else "Phishing"
            confidence = round(max(probabilities) * 100, 1)
            if result == "Phishing":
                top_features = get_top_reasons(features_dict)
                reasons = [FRIENDLY_NAMES.get(f, f) for f in top_features]
            else:
                content_flag = check_page_content(url, domain)
                if content_flag:
                    result = "Phishing"
                    confidence = 90.0
                    reasons = [content_flag]

        save_to_history(url, result, confidence)

    history = get_recent_history()
    return render_template("index.html", result=result, confidence=confidence, reasons=reasons, history=history, submitted_url=submitted_url)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
