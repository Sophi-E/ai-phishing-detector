import re
import os
import ssl
import socket
import whois
import dns.resolver
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")

DEFAULT_TIMEOUT = 7
UA = {"User-Agent": "Mozilla/5.0 (PhishingDetector/1.0)"}

def _ensure_scheme(url: str) -> str:
    if not re.match(r'^https?://', url, flags=re.I):
        return "http://" + url
    return url

def _domain(url: str) -> str:
    return urlparse(url).netloc.lower()

def _fetch(url: str):
    """Fetch page HTML (follow redirects), return (final_url, html, response)."""
    try:
        r = requests.get(_ensure_scheme(url), headers=UA, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        return r.url, r.text, r
    except Exception:
        return url, "", None

def _is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False

def _count_external_total(url: str, soup: BeautifulSoup, selectors):
    dom = _domain(url)
    total, external = 0, 0
    for name, attr in selectors:
        from bs4.element import Tag
        for tag in soup.find_all(name):
            if not isinstance(tag, Tag):
                continue
            href = tag.get(attr)
            if not href:
                continue
            total += 1
            absu = urljoin(url, str(href))
            if _domain(absu) != dom:
                external += 1
    return external, total

def _whois(domain: str):
    try:
        return whois.whois(domain)
    except Exception:
        return None

def _dns_has_record(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except Exception:
        return False

def _ssl_valid(hostname: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert is not None
    except Exception:
        return False

def _virustotal_domain_attrs(domain: str):
    if not VT_API_KEY:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("attributes", {})
    except Exception:
        pass
    return None

def _extract_script_text(soup: BeautifulSoup) -> str:
    return " ".join([s.get_text(" ", strip=True) for s in soup.find_all("script")])

# -----------------------------
# Feature encodings follow UCI style: -1 (legit), 0 (suspicious), 1 (phishing)
# -----------------------------

def having_IP_Address(url: str) -> int:
    return 1 if _is_ip(_domain(url)) else -1

def URL_Length(url: str) -> int:
    L = len(_ensure_scheme(url))
    if L < 54: return -1
    if L <= 75: return 0
    return 1

def Shortining_Service(url: str) -> int:
    pat = r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|buff\.ly|tiny\.cc|bitly\.com|rebrand\.ly)"
    return 1 if re.search(pat, url, flags=re.I) else -1

def having_At_Symbol(url: str) -> int:
    return 1 if "@" in url else -1

def double_slash_redirecting(url: str) -> int:
    idx = _ensure_scheme(url).find("//", 7)
    return 1 if idx != -1 else -1

def Prefix_Suffix(url: str) -> int:
    return 1 if "-" in _domain(url) else -1

def having_Sub_Domain(url: str) -> int:
    host = _domain(url)
    # strip common TLD parts (rough heuristic)
    parts = host.split(".")
    if _is_ip(host):
        return 1
    if len(parts) <= 2: return -1
    if len(parts) == 3: return 0
    return 1

def SSLfinal_State(url: str) -> int:
    host = _domain(url)
    if host and _ssl_valid(host):
        return -1
    return 1

def Domain_registeration_length(url: str) -> int:
    w = _whois(_domain(url))
    if not w or not getattr(w, "expiration_date", None):
        return 1
    exp = w.expiration_date
    if isinstance(exp, list): exp = exp[0]
    if not exp: return 1
    if isinstance(exp, datetime): 
        days = (exp.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    else:
        try:
            exp = datetime.strptime(str(exp), "%Y-%m-%d")
            days = (exp - datetime.utcnow()).days
        except Exception:
            return 1
    return -1 if days >= 365 else 1

def Favicon(url: str) -> int:
    final_url, html, _ = _fetch(url)
    if not html: return 0
    dom = _domain(final_url)
    soup = BeautifulSoup(html, "html.parser")
    from bs4.element import Tag
    icons = [
        link for link in soup.find_all("link")
        if isinstance(link, Tag) and link.get("rel") and any("icon" in str(rel).lower() for rel in link.get("rel") or [])
    ]
    if not icons: return -1
    for ic in icons:
        href = ic.get("href")
        if not href: continue
        absu = urljoin(final_url, str(href))
        if _domain(absu) != dom:
            return 1
    return -1

def port(url: str) -> int:
    netloc = urlparse(_ensure_scheme(url)).netloc
    if ":" in netloc:
        port = netloc.split(":")[-1]
        if port not in ("80", "443"):
            return 1
    return -1

def HTTPS_token(url: str) -> int:
    # 'https' appearing in the domain like 'https-example.com'
    return 1 if re.search(r"https", _domain(url), flags=re.I) else -1

def Request_URL(url: str) -> int:
    final_url, html, _ = _fetch(url)
    if not html: return 0
    soup = BeautifulSoup(html, "html.parser")
    external, total = _count_external_total(
        final_url, soup,
        [("img", "src"), ("video", "src"), ("audio", "src"),
         ("embed", "src"), ("iframe", "src"), ("script", "src"), ("link", "href")]
    )
    if total == 0: return -1
    perc = (external / total) * 100
    if perc < 22: return -1
    if perc <= 61: return 0
    return 1

def URL_of_Anchor(url: str) -> int:
    final_url, html, _ = _fetch(url)
    if not html: return 0
    dom = _domain(final_url)
    soup = BeautifulSoup(html, "html.parser")
    total, bad = 0, 0
    from bs4.element import Tag
    for a in soup.find_all("a"):
        if not isinstance(a, Tag):
            continue
        href = a.get("href")
        if not href: 
            total += 1; bad += 1; continue
        href_l = str(href).strip().lower()
        total += 1
        if href_l in ("#", "#content", "#skip"):
            bad += 1
            continue
        if href_l.startswith("javascript:"):
            bad += 1
            continue
        absu = urljoin(final_url, str(href))
        if _domain(absu) != dom:
            bad += 1
    if total == 0: return -1
    perc = (bad / total) * 100
    if perc < 31: return -1
    if perc <= 67: return 0
    return 1

def Links_in_tags(url: str) -> int:
    final_url, html, _ = _fetch(url)
    if not html: return 0
    dom = _domain(final_url)
    soup = BeautifulSoup(html, "html.parser")
    tags = []
    tags += soup.find_all("meta")
    tags += soup.find_all("script")
    tags += soup.find_all("link")
    total, external = 0, 0
    for t in tags:
        href = t.get("href") or t.get("src")
        if not href: 
            continue
        total += 1
        absu = urljoin(final_url, str(href))
        if _domain(absu) != dom:
            external += 1
    if total == 0: return -1
    perc = (external / total) * 100
    if perc < 17: return -1
    if perc <= 81: return 0
    return 1

def SFH(url: str) -> int:
    final_url, html, _ = _fetch(url)
    if not html: return 0
    dom = _domain(final_url)
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    if not forms: return -1
    from bs4.element import Tag
    for f in forms:
        if not isinstance(f, Tag):
            continue
        act = str(f.get("action") or "").strip()
        if act == "" or act.lower() == "about:blank": 
            return 1
        absu = urljoin(final_url, act)
        if _domain(absu) != dom:
            return 1
    return -1

def Submitting_to_email(url: str) -> int:
    final_url, html, _ = _fetch(url)
    if not html: return -1
    soup = BeautifulSoup(html, "html.parser")
    if "mailto:" in html.lower():
        return 1
    from bs4.element import Tag
    for f in soup.find_all("form"):
        if not isinstance(f, Tag):
            continue
        act = str(f.get("action") or "").lower()
        if "mailto:" in act:
            return 1
    return -1

def Abnormal_URL(url: str) -> int:
    # If domain doesn't resolve => abnormal
    return 1 if not _dns_has_record(_domain(url)) else -1

def Redirect(url: str) -> int:
    try:
        r = requests.get(_ensure_scheme(url), headers=UA, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        hops = len(r.history)
        return 1 if hops > 2 else -1
    except Exception:
        return 0

def on_mouseover(url: str) -> int:
    _, html, _ = _fetch(url)
    if not html: return -1
    if re.search(r"onmouseover\s*=", html, flags=re.I):
        return 1
    return -1

def RightClick(url: str) -> int:
    _, html, _ = _fetch(url)
    if not html: return -1
    if re.search(r"(event\.button\s*==\s*2|contextmenu\s*=\s*['\"]?return\s*false)", html, flags=re.I):
        return 1
    return -1

def popUpWidnow(url: str) -> int:
    _, html, _ = _fetch(url)
    if not html: return -1
    if re.search(r"window\.open\s*\(", html, flags=re.I):
        return 1
    return -1

def Iframe(url: str) -> int:
    _, html, _ = _fetch(url)
    if not html: return -1
    soup = BeautifulSoup(html, "html.parser")
    if soup.find("iframe"):
        return 1
    return -1

def age_of_domain(url: str) -> int:
    w = _whois(_domain(url))
    if not w or not getattr(w, "creation_date", None):
        return 1
    cd = w.creation_date
    if isinstance(cd, list): cd = cd[0]
    if not cd: return 1
    if not isinstance(cd, datetime):
        try:
            cd = datetime.strptime(str(cd), "%Y-%m-%d")
        except Exception:
            return 1
    days = (datetime.utcnow() - cd.replace(tzinfo=None)).days
    return -1 if days >= 180 else 1

def DNSRecord(url: str) -> int:
    # phishing if DNS missing
    return -1 if _dns_has_record(_domain(url)) else 1

def web_traffic(url: str) -> int:
    # Approx via VirusTotal popularity ranks if available
    attrs = _virustotal_domain_attrs(_domain(url))
    if attrs and "popularity_ranks" in attrs and attrs["popularity_ranks"]:
        # get any rank
        try:
            ranks = attrs["popularity_ranks"]
            any_rank = min([v["rank"] for v in ranks.values() if "rank" in v] or [999999])
            if any_rank < 100000: return -1
            if any_rank <= 300000: return 0
            return 1
        except Exception:
            return 0
    # if unknown ⇒ suspicious
    return 1

def Page_Rank(url: str) -> int:
    # Heuristic using VT reputation votes
    attrs = _virustotal_domain_attrs(_domain(url))
    if attrs:
        harmless = attrs.get("total_votes", {}).get("harmless", 0)
        malicious = attrs.get("total_votes", {}).get("malicious", 0)
        if malicious > harmless: return 1
        if harmless > 0: return -1
    return 0

def Google_Index(url: str) -> int:
    # Use VT presence as proxy for being "known" on the internet
    attrs = _virustotal_domain_attrs(_domain(url))
    if attrs:
        return -1  # known
    return 1      # unknown

def Links_pointing_to_page(url: str) -> int:
    # Approximate with count of internal anchors (not true backlinks)
    final_url, html, _ = _fetch(url)
    if not html: return 0
    dom = _domain(final_url)
    soup = BeautifulSoup(html, "html.parser")
    from bs4.element import Tag
    count_internal = 0
    for a in soup.find_all("a"):
        if not isinstance(a, Tag):
            continue
        href = a.get("href")
        if not href: continue
        absu = urljoin(final_url, str(href))
        if _domain(absu) == dom:
            count_internal += 1
    if count_internal == 0: return 1
    if count_internal <= 2: return 0
    return -1

def Statistical_report(url: str) -> int:
    # Domain flagged by VT?
    attrs = _virustotal_domain_attrs(_domain(url))
    if not attrs:
        return 0
    stats = attrs.get("last_analysis_stats", {})
    if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
        return 1
    return -1

def extract_features(url: str):
    url = _ensure_scheme(url)
    return [
        having_IP_Address(url),
        URL_Length(url),
        Shortining_Service(url),
        having_At_Symbol(url),
        double_slash_redirecting(url),
        Prefix_Suffix(url),
        having_Sub_Domain(url),
        SSLfinal_State(url),
        Domain_registeration_length(url),
        Favicon(url),
        port(url),
        HTTPS_token(url),
        Request_URL(url),
        URL_of_Anchor(url),
        Links_in_tags(url),
        SFH(url),
        Submitting_to_email(url),
        Abnormal_URL(url),
        Redirect(url),
        on_mouseover(url),
        RightClick(url),
        popUpWidnow(url),
        Iframe(url),
        age_of_domain(url),
        DNSRecord(url),
        web_traffic(url),
        Page_Rank(url),
        Google_Index(url),
        Links_pointing_to_page(url),
        Statistical_report(url),
    ]
