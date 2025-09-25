import re
import socket
import whois
import requests
import datetime
import joblib
import streamlit as st
from urllib.parse import urlparse
from bs4 import BeautifulSoup
model = joblib.load("phishing_rf_model.pk9")
def having_ip_address(url):
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    return 1 if ip_pattern.search(url) else -1

def url_length(url):
    return 1 if len(url) < 54 else 0 if len(url) <= 75 else -1

def shortening_service(url):
    shortening_services = r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|buff\.ly"
    return -1 if re.search(shortening_services, url) else 1

def having_at_symbol(url):
    return -1 if "@" in url else 1

def double_slash_redirecting(url):
    return -1 if url.rfind("//") > 6 else 1

def prefix_suffix(url):
    return -1 if "-" in urlparse(url).netloc else 1

def having_sub_domain(url):
    dots = urlparse(url).netloc.split(".")
    return -1 if len(dots) > 3 else 0 if len(dots) == 3 else 1

def ssl_final_state(url):
    try:
        response = requests.get(url, timeout=5)
        return 1 if url.startswith("https") else -1
    except:
        return -1

def domain_registration_length(domain):
    try:
        w = whois.whois(domain)
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return 1 if expiration_date and (expiration_date - datetime.datetime.now()).days > 365 else -1
    except:
        return -1

def favicon(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        return 1 if icon and urlparse(icon.get("href", "")).netloc == urlparse(url).netloc else -1
    except:
        return -1

def port(url):
    try:
        domain = urlparse(url).netloc
        socket.create_connection((domain, 80), timeout=2)
        return 1
    except:
        return -1

def https_token(url):
    return -1 if "https" in urlparse(url).netloc else 1

def request_url(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        imgs = soup.find_all("img", src=True)
        total = len(imgs)
        linked = sum(1 for img in imgs if urlparse(img["src"]).netloc and urlparse(img["src"]).netloc != urlparse(url).netloc)
        return 1 if total == 0 else (1 if linked / total < 0.22 else 0 if linked / total < 0.61 else -1)
    except:
        return -1

def url_of_anchor(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        anchors = soup.find_all("a", href=True)
        total = len(anchors)
        linked = sum(1 for a in anchors if urlparse(a["href"]).netloc and urlparse(a["href"]).netloc != urlparse(url).netloc)
        return 1 if total == 0 else (1 if linked / total < 0.31 else 0 if linked / total < 0.67 else -1)
    except:
        return -1

def links_in_tags(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        metas = soup.find_all("meta")
        links = soup.find_all("link")
        scripts = soup.find_all("script")
        total = len(metas) + len(links) + len(scripts)
        return 1 if total < 2 else 0 if total <= 5 else -1
    except:
        return -1

def sfh(url):
    return 1  # simplified placeholder

def submitting_to_email(url):
    return -1 if "mailto:" in url else 1

def abnormal_url(url):
    try:
        hostname = urlparse(url).netloc
        w = whois.whois(hostname)
        return 1 if w.domain_name else -1
    except:
        return -1

def redirect(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return -1 if len(response.history) > 2 else 1
    except:
        return -1

def on_mouseover(url):
    return 1  # simplified placeholder

def right_click(url):
    return 1  # simplified placeholder

def popup_window(url):
    return 1  # simplified placeholder

def iframe(url):
    return 1  # simplified placeholder

def age_of_domain(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return 1 if creation_date and (datetime.datetime.now() - creation_date).days > 180 else -1
    except:
        return -1

def dns_record(url):
    try:
        domain = urlparse(url).netloc
        socket.gethostbyname(domain)
        return 1
    except:
        return -1

def web_traffic(url):
    return 0  # placeholder since Alexa API is retired

def page_rank(url):
    return 0  # placeholder

def google_index(url):
    try:
        search_url = f"https://www.google.com/search?q=site:{url}"
        response = requests.get(search_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        return 1 if "did not match any documents" not in response.text else -1
    except:
        return -1

def links_pointing(url):
    return 0  # simplified placeholder

def statistical_report(url):
    return -1 if re.search(r"paypal|login|banking|update", url) else 1

def extract_features(url):
    domain = urlparse(url).netloc
    features = [
        having_ip_address(url),
        url_length(url),
        shortening_service(url),
        having_at_symbol(url),
        double_slash_redirecting(url),
        prefix_suffix(url),
        having_sub_domain(url),
        ssl_final_state(url),
        domain_registration_length(domain),
        favicon(url),
        port(url),
        https_token(url),
        request_url(url),
        url_of_anchor(url),
        links_in_tags(url),
        sfh(url),
        submitting_to_email(url),
        abnormal_url(url),
        redirect(url),
        on_mouseover(url),
        right_click(url),
        popup_window(url),
        iframe(url),
        age_of_domain(url),
        dns_record(url),
        web_traffic(url),
        page_rank(url),
        google_index(url),
        links_pointing(url),
        statistical_report(url)
    ]
    return features

st.title("🔐 Phishing Website Detection")
url = st.text_input("Enter a URL to check:")

if st.button("Check"):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    if prediction == 1:
        st.success("✅ Legitimate Website")
    else:
        st.error("⚠️ Phishing Website Detected")


