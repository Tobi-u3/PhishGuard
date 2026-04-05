from flask import Flask, request, render_template
import joblib
import re
import os
import socket
import dns.resolver
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from dotenv import load_dotenv
import pandas as pd
import requests
import whois
from datetime import datetime
import tldextract

load_dotenv()

app = Flask(__name__)
BASE_DIR = Path(__file__).parent
model = joblib.load(BASE_DIR / 'phishguard_model.pkl')

VT_API_KEY  = os.getenv('VT_API_KEY')
GSB_API_KEY = os.getenv('GSB_API_KEY')

WHITELIST = [
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'github.com', 'wikipedia.org',
    'amazon.com', 'netflix.com', 'microsoft.com', 'apple.com',
    'stackoverflow.com', 'reddit.com', 'whatsapp.com', 'zoom.us',
    'flipkart.com', 'naukri.com', 'irctc.co.in', 'paytm.com'
]

SHORTENED = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly',
             'buff.ly','is.gd','rb.gy','shorte.st','adf.ly']

def get_domain(url):
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        return re.sub(r'^www\.', '', urlparse(url).netloc)
    except:
        return ''

def is_whitelisted(url):
    domain = get_domain(url)
    return any(domain == s or domain.endswith('.' + s) for s in WHITELIST)

def check_virustotal(url):
    try:
        headers = {'x-apikey': VT_API_KEY}
        r = requests.post('https://www.virustotal.com/api/v3/urls',
                          headers=headers, data={'url': url}, timeout=10)
        if r.status_code == 200:
            scan_id = r.json()['data']['id']
            result = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{scan_id}',
                headers=headers, timeout=10)
            stats = result.json()['data']['attributes']['stats']
            return stats.get('malicious', 0) + stats.get('suspicious', 0)
    except:
        pass
    return 0

def check_google_safe_browsing(url):
    try:
        endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}'
        payload = {
            'client': {'clientId': 'phishguard', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        r = requests.post(endpoint, json=payload, timeout=10)
        if r.status_code == 200:
            return bool(r.json().get('matches'))
    except:
        pass
    return False

def check_whois(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        age = (datetime.now() - creation_date).days if creation_date else -1
        exp = (expiration_date - datetime.now()).days if expiration_date else -1
        return age, exp
    except:
        return -1, -1

def count_char(s, ch):
    return s.count(ch) if s else -1

def extract_features(url):
    raw_url = re.sub(r'^https?://', '', url)
    try:
        full = url if url.startswith('http') else 'http://' + url
        parsed  = urlparse(full)
        domain  = parsed.netloc
        path    = parsed.path
        params  = parsed.query
    except:
        domain = path = params = ''

    clean_domain = re.sub(r'^www\.', '', domain)

    # Split path into directory and file
    path_parts = path.rsplit('/', 1)
    directory  = path_parts[0] if len(path_parts) > 1 else ''
    filename   = path_parts[1] if len(path_parts) > 1 else ''

    ext = tldextract.extract(full if url.startswith('http') else 'http://'+url)
    tld = ext.suffix

    vowels = sum(1 for c in clean_domain.lower() if c in 'aeiou')
    is_ip  = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', clean_domain) else 0

    # Check if server/client in domain
    server_client = 1 if any(w in clean_domain.lower() for w in ['server','client']) else 0

    # TLD in params
    tld_in_params = 1 if tld and tld in params else 0

    # Count params
    qty_params = len(parse_qs(params))

    # Email in URL
    email_in_url = 1 if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw_url) else 0

    # URL shortened
    url_shortened = 1 if any(s in domain for s in SHORTENED) else 0

    # Network features — use WHOIS for domain times
    domain_age, domain_exp = check_whois(clean_domain)

    # Try DNS for nameservers, mx, ip
    try:
        qty_ip = len(socket.getaddrinfo(clean_domain, None))
    except:
        qty_ip = -1

    try:
        ns = dns.resolver.resolve(clean_domain, 'NS')
        qty_ns = len(list(ns))
    except:
        qty_ns = -1

    try:
        mx = dns.resolver.resolve(clean_domain, 'MX')
        qty_mx = len(list(mx))
    except:
        qty_mx = -1

    # TTL
    try:
        ans = dns.resolver.resolve(clean_domain, 'A')
        ttl = ans.rrset.ttl
    except:
        ttl = -1

    f = {
        # URL-level
        'qty_dot_url':          count_char(raw_url, '.'),
        'qty_hyphen_url':       count_char(raw_url, '-'),
        'qty_underline_url':    count_char(raw_url, '_'),
        'qty_slash_url':        count_char(raw_url, '/'),
        'qty_questionmark_url': count_char(raw_url, '?'),
        'qty_equal_url':        count_char(raw_url, '='),
        'qty_at_url':           count_char(raw_url, '@'),
        'qty_and_url':          count_char(raw_url, '&'),
        'qty_exclamation_url':  count_char(raw_url, '!'),
        'qty_space_url':        count_char(raw_url, ' '),
        'qty_tilde_url':        count_char(raw_url, '~'),
        'qty_comma_url':        count_char(raw_url, ','),
        'qty_plus_url':         count_char(raw_url, '+'),
        'qty_asterisk_url':     count_char(raw_url, '*'),
        'qty_hashtag_url':      count_char(raw_url, '#'),
        'qty_dollar_url':       count_char(raw_url, '$'),
        'qty_percent_url':      count_char(raw_url, '%'),
        'qty_tld_url':          len(tld) if tld else -1,
        'length_url':           len(raw_url),
        # Domain-level
        'qty_dot_domain':          count_char(clean_domain, '.'),
        'qty_hyphen_domain':       count_char(clean_domain, '-'),
        'qty_underline_domain':    count_char(clean_domain, '_'),
        'qty_slash_domain':        count_char(clean_domain, '/'),
        'qty_questionmark_domain': count_char(clean_domain, '?'),
        'qty_equal_domain':        count_char(clean_domain, '='),
        'qty_at_domain':           count_char(clean_domain, '@'),
        'qty_and_domain':          count_char(clean_domain, '&'),
        'qty_exclamation_domain':  count_char(clean_domain, '!'),
        'qty_space_domain':        count_char(clean_domain, ' '),
        'qty_tilde_domain':        count_char(clean_domain, '~'),
        'qty_comma_domain':        count_char(clean_domain, ','),
        'qty_plus_domain':         count_char(clean_domain, '+'),
        'qty_asterisk_domain':     count_char(clean_domain, '*'),
        'qty_hashtag_domain':      count_char(clean_domain, '#'),
        'qty_dollar_domain':       count_char(clean_domain, '$'),
        'qty_percent_domain':      count_char(clean_domain, '%'),
        'qty_vowels_domain':       vowels,
        'domain_length':           len(clean_domain),
        'domain_in_ip':            is_ip,
        'server_client_domain':    server_client,
        # Directory-level
        'qty_dot_directory':          count_char(directory, '.'),
        'qty_hyphen_directory':       count_char(directory, '-'),
        'qty_underline_directory':    count_char(directory, '_'),
        'qty_slash_directory':        count_char(directory, '/'),
        'qty_questionmark_directory': count_char(directory, '?'),
        'qty_equal_directory':        count_char(directory, '='),
        'qty_at_directory':           count_char(directory, '@'),
        'qty_and_directory':          count_char(directory, '&'),
        'qty_exclamation_directory':  count_char(directory, '!'),
        'qty_space_directory':        count_char(directory, ' '),
        'qty_tilde_directory':        count_char(directory, '~'),
        'qty_comma_directory':        count_char(directory, ','),
        'qty_plus_directory':         count_char(directory, '+'),
        'qty_asterisk_directory':     count_char(directory, '*'),
        'qty_hashtag_directory':      count_char(directory, '#'),
        'qty_dollar_directory':       count_char(directory, '$'),
        'qty_percent_directory':      count_char(directory, '%'),
        'directory_length':           len(directory),
        # File-level
        'qty_dot_file':          count_char(filename, '.'),
        'qty_hyphen_file':       count_char(filename, '-'),
        'qty_underline_file':    count_char(filename, '_'),
        'qty_slash_file':        count_char(filename, '/'),
        'qty_questionmark_file': count_char(filename, '?'),
        'qty_equal_file':        count_char(filename, '='),
        'qty_at_file':           count_char(filename, '@'),
        'qty_and_file':          count_char(filename, '&'),
        'qty_exclamation_file':  count_char(filename, '!'),
        'qty_space_file':        count_char(filename, ' '),
        'qty_tilde_file':        count_char(filename, '~'),
        'qty_comma_file':        count_char(filename, ','),
        'qty_plus_file':         count_char(filename, '+'),
        'qty_asterisk_file':     count_char(filename, '*'),
        'qty_hashtag_file':      count_char(filename, '#'),
        'qty_dollar_file':       count_char(filename, '$'),
        'qty_percent_file':      count_char(filename, '%'),
        'file_length':           len(filename),
        # Params-level
        'qty_dot_params':          count_char(params, '.'),
        'qty_hyphen_params':       count_char(params, '-'),
        'qty_underline_params':    count_char(params, '_'),
        'qty_slash_params':        count_char(params, '/'),
        'qty_questionmark_params': count_char(params, '?'),
        'qty_equal_params':        count_char(params, '='),
        'qty_at_params':           count_char(params, '@'),
        'qty_and_params':          count_char(params, '&'),
        'qty_exclamation_params':  count_char(params, '!'),
        'qty_space_params':        count_char(params, ' '),
        'qty_tilde_params':        count_char(params, '~'),
        'qty_comma_params':        count_char(params, ','),
        'qty_plus_params':         count_char(params, '+'),
        'qty_asterisk_params':     count_char(params, '*'),
        'qty_hashtag_params':      count_char(params, '#'),
        'qty_dollar_params':       count_char(params, '$'),
        'qty_percent_params':      count_char(params, '%'),
        'params_length':           len(params),
        'tld_present_params':      tld_in_params,
        'qty_params':              qty_params,
        'email_in_url':            email_in_url,
        # Network features
        'time_response':           -1,
        'domain_spf':              -1,
        'asn_ip':                  -1,
        'time_domain_activation':  domain_age,
        'time_domain_expiration':  domain_exp,
        'qty_ip_resolved':         qty_ip,
        'qty_nameservers':         qty_ns,
        'qty_mx_servers':          qty_mx,
        'ttl_hostname':            ttl,
        'tls_ssl_certificate':     1 if url.startswith('https') else 0,
        'qty_redirects':           -1,
        'url_google_index':        -1,
        'domain_google_index':     -1,
        'url_shortened':           url_shortened,
    }
    return f

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    url    = None
    details = []
    ml_prob_phish = 0

    if request.method == 'POST':
        url = request.form['url'].strip()

        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', url) if url else None
        if ip_match:
            ip = ip_match.group(1)
            private = (
                ip.startswith('192.168.') or
                ip.startswith('10.') or
                ip.startswith('172.') or
                ip == '127.0.0.1'
            )
            if private:
                result = 'PHISHING'
                details.append(('danger', '🔴 Private IP address in URL — suspicious'))
                return render_template('index.html', result=result, url=url,
                                       details=details, ml_prob=100)

        if is_whitelisted(url):
            result = 'SAFE'
            ml_prob_phish = 2
            details.append(('safe', '✅ Domain is in trusted whitelist'))
        else:
            flags = 0
            gsb = check_google_safe_browsing(url)
            if gsb:
                flags += 2
                details.append(('danger', '🔴 Flagged by Google Safe Browsing'))
            else:
                details.append(('safe', '✅ Passed Google Safe Browsing'))

            vt = check_virustotal(url)
            if vt >= 2:
                flags += 2
                details.append(('danger', f'🔴 Flagged by {vt} VirusTotal engines'))
            elif vt == 1:
                flags += 1
                details.append(('warn', f'⚠️ VirusTotal: {vt} engine flagged (low risk)'))
            else:
                details.append(('safe', f'✅ VirusTotal: clean'))

            clean_domain = get_domain(url)
            age, exp = check_whois(clean_domain)
            if age != -1:
                if age < 180:
                    flags += 1
                    details.append(('warn', f'⚠️ Domain is only {age} days old'))
                else:
                    details.append(('safe', f'✅ Domain age: {age} days'))
            else:
                details.append(('warn', '⚠️ Could not verify domain age'))

            features = extract_features(url)
            df = pd.DataFrame([features])
            prediction    = model.predict(df)[0]
            proba         = model.predict_proba(df)[0]
            ml_prob_phish = round(proba[1] * 100)

            if prediction == 1:
                flags += 1
                details.append(('warn', f'⚠️ ML Model flagged as suspicious'))
            else:
                if ml_prob_phish < 40:
                    details.append(('safe', f'✅ ML Model: URL pattern looks safe'))
                else:
                    details.append(('warn', f'⚠️ ML Model: inconclusive ({ml_prob_phish}% phishing)'))

            # Keyword-based override
            phish_keywords = ['secure', 'verify', 'update', 'login', 'signin',
                  'account', 'confirm', 'banking', 'paypal', 'amazon',
                  'apple', 'microsoft', 'password', 'credential']
            clean = get_domain(url).lower()
            brand_domains = ['paypal.com','amazon.com','apple.com','microsoft.com',
                 'google.com','facebook.com','netflix.com','bank']
            keyword_hit = sum(1 for k in phish_keywords if k in clean)
            brand_spoof = any(b.split('.')[0] in clean for b in brand_domains) and \
                          not any(clean == b or clean.endswith('.'+b) for b in brand_domains)
            if keyword_hit >= 2 or brand_spoof:
                flags += 2
                details.append(('danger', f'🔴 Suspicious domain pattern detected'))

            hard_flags = sum(1 for tag, _ in details if tag == 'danger')
            age_unknown = age == -1
            ml_high = ml_prob_phish >= 60

            if hard_flags >= 1:
                result = 'PHISHING'
            elif ml_high and age_unknown:
                result = 'PHISHING'
            elif flags >= 3:
                result = 'PHISHING'
            else:
                result = 'SAFE'

    return render_template('index.html',
                           result=result,
                           url=url,
                           details=details,
                           ml_prob=ml_prob_phish)

if __name__ == '__main__':
    app.run(debug=True)
