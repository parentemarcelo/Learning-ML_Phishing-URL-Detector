import re
import socket
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import joblib
import warnings
import pandas as pd
from flask import Flask, request, jsonify

# Change to the path where your model is stored
model = joblib.load('./models/lgbm.pkl')

def extract_url_features(url):
    features = {}

    # Passive features extraction
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features['NumDots'] = url.count('.')
    features['SubdomainLevel'] = hostname.count('.') if hostname else 0
    features['PathLevel'] = path.count('/') if path else 0
    features['UrlLength'] = len(url)
    features['NumDash'] = url.count('-')
    features['NumDashInHostname'] = hostname.count('-') if hostname else 0
    features['NumQueryComponents'] = len(parse_qs(query))
    features['NumDigits'] = sum(c.isdigit() for c in url)
    features['NoHttps'] = 1 if parsed.scheme == 'https' else 0
    try: 
        socket.inet_aton(hostname)
        features['IpAddress'] = 1
    except:
        features['IpAddress'] = 0

    features['TildeSymbol'] = 1 if '~' in url else 0
    features['NumUnderscore'] = url.count('_')
    features['NumAmpersand'] = url.count('&')
    features['RandomString'] = 1 if re.search(r'[a-zA-Z0-9]{10,}', url) else 0
    parts = hostname.split('.') if hostname else []
    features['DomainInPaths'] = 1 if hostname and parts[-1] in path else 0
    features['HostnameLength'] = len(hostname)
    features['PathLength'] = len(path)
    features['QueryLength'] = len(query)
    sensitive_words = ['login', 'secure', 'account', 'update', 'bank', 'verify', 'signin', 'password', 'confirm', 'ebayisapi', 'webscr', 'paypal']
    features['NumSensitiveWords'] = sum(word in url.lower() for word in sensitive_words)
 

    # Active features extraction
    try:
        head = requests.head(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        size = int(head.headers.get('Content-Length', 0))
        if size and size < 100_000_000:
            resp = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                links = soup.find_all('a', href=True)
                if links:
                    ext_links = [link for link in links if hostname not in urlparse(str(link.get('href') or '')).netloc]
                    features['PctExtHyperlinks'] = len(ext_links) / len(links)
                else:
                    features['PctExtHyperlinks'] = 0
                
                resources = soup.find_all(['img', 'script', 'link'], src=True)
                if resources:
                    ext_resources = [res for res in resources if hostname not in urlparse(str(res.get('src') or res.get('href') or '')).netloc]
                    features['PctExtResourceUrls'] = len(ext_resources) / len(resources)
                else:
                    features['PctExtResourceUrls'] = 0
                
                null_links = [link for link in links if link['href'] in ('', '#', '/', url, 'javascript::void(0)', 'JavaScript:: void(0)')]
                features['PctNullSelfRedirectHyperlinks'] = len(null_links) / len(links) if links else 0

                features['FrequentDomainNameMismatch'] = 1 if features['PctExtHyperlinks'] > 0.5 else 0

                forms = soup.find_all('form')
                features['SubmitInfoToEmail'] = 1 if any('mailto:' in str(form) for form in forms) else 0

                metas = soup.find_all(['meta', 'script', 'link'])
                if metas:
                    ext_metas = [meta for meta in metas if hostname not in urlparse(str(meta.get('src') or meta.get('href') or '')).netloc]
                    ratio = len(ext_metas) / len(metas)
                    if ratio > 0.66:
                        features['ExtMetaScriptLinkRT'] = 1
                    elif ratio > 0.33:
                        features['ExtMetaScriptLinkRT'] = 0
                    else:
                        features['ExtMetaScriptLinkRT'] = -1
                else:
                    features['ExtMetaScriptLinkRT'] = None

                features['InsecureForms'] = 1 if any(form.get('action', '').startswith('http://') for form in forms) else 0
                features['IframeOrFrame'] = 1 if soup.find_all(['iframe', 'frame']) else 0

                if links:
                    suspicious = 0
                    for link in links:
                        href = str(link.get('href') or '').lower()
                        netloc = urlparse(href).netloc.lower()
                        if netloc and hostname.lower() not in netloc:
                            suspicious += 1
                        elif href.startswith('#'):
                            suspicious += 1
                        elif 'javascript::void(0)' in href:
                            suspicious += 1
                    pcd = suspicious / len(links)
                    if pcd > 0.66:
                        features['PctExtNullSelfRedirectHyperlinksRT'] = 1
                    elif pcd > 0.33:
                        features['PctExtNullSelfRedirectHyperlinksRT'] = 0
                    else:
                        features['PctExtNullSelfRedirectHyperlinksRT'] = -1            
            else:
                features['PctExtHyperlinks'] = None
                features['PctExtResourceUrls'] = None
                features['PctNullSelfRedirectHyperlinks'] = None
                features['FrequentDomainNameMismatch'] = None
                features['SubmitInfoToEmail'] = None
                features['ExtMetaScriptLinkRT'] = None
                features['InsecureForms'] = None
                features['IframeOrFrame'] = None
                features['PctExtNullSelfRedirectHyperlinksRT'] = None
        else:
                features['PctExtHyperlinks'] = None
                features['PctExtResourceUrls'] = None
                features['PctNullSelfRedirectHyperlinks'] = None
                features['FrequentDomainNameMismatch'] = None
                features['SubmitInfoToEmail'] = None
                features['ExtMetaScriptLinkRT'] = None
                features['InsecureForms'] = None
                features['IframeOrFrame'] = None
                features['PctExtNullSelfRedirectHyperlinksRT'] = None
    except:
        features['PctExtHyperlinks'] = None
        features['PctExtResourceUrls'] = None
        features['PctNullSelfRedirectHyperlinks'] = None
        features['FrequentDomainNameMismatch'] = None
        features['SubmitInfoToEmail'] = None
        features['ExtMetaScriptLinkRT'] = None
        features['InsecureForms'] = None
        features['IframeOrFrame'] = None
        features['PctExtNullSelfRedirectHyperlinksRT'] = None

    return features


def classify_url(url, model=model):

    try:
        resp = requests.head(url, allow_redirects=True, timeout=5)
        if resp.status_code == 200:
            status = 'OK'
        else:
            status = 'UNREACHABLE'
    except:
        status = 'UNREACHABLE'

    features = extract_url_features(url)

    expected_features = model.feature_names_in_
    X_input = pd.DataFrame([[features.get(f, None) for f in expected_features]], columns=expected_features)
    
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', category=UserWarning)
        prediction = model.predict(X_input)[0]
        proba = model.predict_proba(X_input)[0][prediction]

    return {'status': status, 'label': 'PHISHING' if prediction == 1 else 'LEGIT', 'probability': float(round(proba, 3))}

app = Flask(__name__)

@app.route('/classify', methods=['GET'])
def classify():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL parameter is missing"}), 400
    
    result = classify_url(url)
    return jsonify({"url": url, "classification": result})

if __name__ == "__main__":
    app.run(debug=True, port=5001) # Change port if needed
