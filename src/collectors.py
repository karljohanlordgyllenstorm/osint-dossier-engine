import asyncio
from datetime import datetime, timezone
import re
import socket
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as ET
import aiohttp
from bs4 import BeautifulSoup
import dns.resolver
from duckduckgo_search import DDGS
import whois


def classify_target(target: str) -> dict:
  target = target.strip()
  if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
    return {"type": "ip", "value": target}
  elif re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", target):
    return {"type": "domain", "value": target.lower()}
  elif any(
      s in target.lower()
      for s in ["ab", "inc", "corp", "ltd", "gmbh", "llc", "aktiebolag"]
  ):
    return {"type": "organization", "value": target}
  return {"type": "person", "value": target}


def is_relevant_hit(result: dict, target: str, city: str = "") -> bool:
  """Filtrerar bort skräpresultat genom att kräva att målets namn/ord finns i titel eller beskrivning."""
  href = result.get("href", "").lower()
  spam_domains = [
      "answers.com",
      "calculateme.com",
      "salarycalculator.info",
      "savvydollar.com",
      "finatopia.com",
      "pinterest.",
      "amazon.com",
      "yelp.com",
      "tripadvisor.com",
      "zoo.org",
      "microsoft.com",
      "gasstations-nearme.com",
  ]
  if any(sd in href for sd in spam_domains):
    return False

  text = f"{result.get('title', '')} {result.get('body', '')}".lower()
  tokens = [t.lower() for t in target.split() if len(t) > 2]
  if not tokens:
    return True

  name_match = all(t in text for t in tokens)
  if city and len(city.strip()) > 2:
    return name_match and (city.strip().lower() in text)
  return name_match


def get_dns_records(domain: str) -> dict:
  records = {}
  for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CAA"]:
    try:
      answers = dns.resolver.resolve(domain, rtype, lifetime=5)
      records[rtype] = [r.to_text().strip('"') for r in answers]
    except Exception:
      records[rtype] = []

  try:
    dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
    records["DMARC"] = [r.to_text().strip('"') for r in dmarc]
  except Exception:
    records["DMARC"] = []
  return {"source": "dns", "data": records}


def get_whois_info(domain: str) -> dict:
  try:
    w = whois.whois(domain)
    return {
        "source": "whois",
        "data": {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers,
            "org": w.org,
            "country": w.country,
        },
    }
  except Exception as e:
    return {"source": "whois", "error": str(e), "data": {}}


def get_ssl_info(domain: str) -> dict:
  try:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=5) as sock:
      with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
        cert = ssock.getpeercert()
        san = [x[1] for x in cert.get("subjectAltName", [])]
        return {
            "source": "ssl",
            "data": {
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "notAfter": cert.get("notAfter"),
                "notBefore": cert.get("notBefore"),
                "alt_names": san[:25],
            },
        }
  except Exception as e:
    return {"source": "ssl", "error": str(e), "data": {}}


async def fetch_http_security_and_tech(
    session: aiohttp.ClientSession, domain: str
) -> dict:
  url = f"https://{domain}"
  sec_headers = [
      "Strict-Transport-Security",
      "Content-Security-Policy",
      "X-Frame-Options",
      "X-Content-Type-Options",
      "Referrer-Policy",
      "Permissions-Policy",
  ]
  try:
    async with session.get(url, timeout=10, allow_redirects=True) as resp:
      headers = dict(resp.headers)
      html = await resp.text(errors="ignore")

      present = {h: headers.get(h) for h in sec_headers if h in headers}
      missing = [h for h in sec_headers if h not in headers]

      tech = []
      html_lower = html.lower()
      server = headers.get("Server", "")
      if server:
        tech.append(f"Server: {server}")
      if "x-powered-by" in (k.lower() for k in headers):
        tech.append(f"Powered-By: {headers.get('X-Powered-By')}")
      if "wp-content" in html_lower or "wordpress" in html_lower:
        tech.append("WordPress")
      if "shopify" in html_lower:
        tech.append("Shopify")
      if "__next" in html_lower or "_next/static" in html_lower:
        tech.append("Next.js / React")
      if "cloudflare" in server.lower() or "cf-ray" in (
          k.lower() for k in headers
      ):
        tech.append("Cloudflare CDN/WAF")

      return {
          "source": "http_headers_tech",
          "data": {
              "final_url": str(resp.url),
              "status_code": resp.status,
              "present_security_headers": present,
              "missing_security_headers": missing,
              "detected_technologies": tech,
          },
      }
  except Exception as e:
    return {"source": "http_headers_tech", "error": str(e), "data": {}}


async def fetch_public_contacts_and_socials(
    session: aiohttp.ClientSession, domain: str
) -> dict:
  """Extraherar publika e-postadresser och sociala kanaler från domänen."""
  url = f"https://{domain}"
  social_domains = [
      "linkedin.com",
      "twitter.com",
      "x.com",
      "youtube.com",
      "github.com",
      "instagram.com",
      "facebook.com",
  ]
  try:
    async with session.get(url, timeout=10, allow_redirects=True) as resp:
      if resp.status == 200:
        html = await resp.text(errors="ignore")
        soup = BeautifulSoup(html, "html.parser")

        emails = set(
            re.findall(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html
            )
        )
        clean_emails = [
            e
            for e in emails
            if not e.lower().endswith((".png", ".jpg", ".svg", ".webp", ".gif"))
        ]

        socials = set()
        for a in soup.find_all("a", href=True):
          href = a["href"].strip()
          if any(sd in href.lower() for sd in social_domains):
            socials.add(href)

        return {
            "source": "public_contacts_socials",
            "data": {
                "emails": sorted(clean_emails)[:15],
                "social_profiles": sorted(list(socials))[:20],
            },
        }
  except Exception as e:
    return {"source": "public_contacts_socials", "error": str(e), "data": {}}
  return {"source": "public_contacts_socials", "data": {}}


async def fetch_well_known_files(
    session: aiohttp.ClientSession, domain: str
) -> dict:
  found = {}
  paths = ["/robots.txt", "/.well-known/security.txt", "/sitemap.xml"]
  for p in paths:
    try:
      async with session.get(f"https://{domain}{p}", timeout=6) as resp:
        if resp.status == 200:
          text = await resp.text(errors="ignore")
          found[p] = text[:600]
    except Exception:
      pass
  return {"source": "well_known_files", "data": found}


async def fetch_crt_sh(session: aiohttp.ClientSession, domain: str) -> dict:
  url = f"https://crt.sh/?q=%.{domain}&output=json"
  try:
    async with session.get(url, timeout=15) as resp:
      if resp.status == 200:
        data = await resp.json(content_type=None)
        subs = set()
        for entry in data:
          for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name and "*" not in name:
              subs.add(name)
        return {"source": "crt.sh", "subdomains": sorted(list(subs))[:150]}
  except Exception as e:
    return {"source": "crt.sh", "error": str(e), "subdomains": []}
  return {"source": "crt.sh", "subdomains": []}


async def fetch_hackertarget_subs(
    session: aiohttp.ClientSession, domain: str
) -> dict:
  url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
  try:
    async with session.get(url, timeout=10) as resp:
      if resp.status == 200:
        text = await resp.text()
        if "API count exceeded" not in text and "error" not in text.lower():
          lines = [
              line.split(",") for line in text.strip().splitlines() if "," in line
          ]
          return {"source": "hackertarget", "hosts": lines[:50]}
  except Exception as e:
    return {"source": "hackertarget", "error": str(e), "hosts": []}
  return {"source": "hackertarget", "hosts": []}


async def fetch_internetdb(session: aiohttp.ClientSession, ip: str) -> dict:
  url = f"https://internetdb.shodan.io/{ip}"
  try:
    async with session.get(url, timeout=10) as resp:
      if resp.status == 200:
        return {"source": "internetdb", "data": await resp.json()}
  except Exception as e:
    return {"source": "internetdb", "error": str(e), "data": {}}
  return {"source": "internetdb", "data": {}}


async def fetch_ip_geo_and_asn(session: aiohttp.ClientSession, ip: str) -> dict:
  url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,asname,reverse"
  try:
    async with session.get(url, timeout=10) as resp:
      if resp.status == 200:
        return {"source": "ip_geo_asn", "data": await resp.json()}
  except Exception as e:
    return {"source": "ip_geo_asn", "error": str(e), "data": {}}
  return {"source": "ip_geo_asn", "data": {}}


async def fetch_urlhaus(session: aiohttp.ClientSession, host: str) -> dict:
  url = "https://urlhaus-api.abuse.ch/v1/host/"
  try:
    async with session.post(url, data={"host": host}, timeout=10) as resp:
      if resp.status == 200:
        data = await resp.json()
        return {
            "source": "urlhaus_threatfeed",
            "data": {
                "query_status": data.get("query_status"),
                "url_count": data.get("url_count", 0),
                "blacklists": data.get("blacklists", {}),
            },
        }
  except Exception as e:
    return {"source": "urlhaus_threatfeed", "error": str(e), "data": {}}
  return {"source": "urlhaus_threatfeed", "data": {}}


async def fetch_wayback(session: aiohttp.ClientSession, domain: str) -> dict:
  url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=40"
  try:
    async with session.get(url, timeout=15) as resp:
      if resp.status == 200:
        data = await resp.json(content_type=None)
        urls = [row[0] for row in data[1:]] if len(data) > 1 else []
        return {"source": "wayback", "urls": urls}
  except Exception as e:
    return {"source": "wayback", "error": str(e), "urls": []}
  return {"source": "wayback", "urls": []}


async def fetch_google_news(
    session: aiohttp.ClientSession, query: str, city: str = "", max_items: int = 8
) -> dict:
  """Hämtar färska nyhetsartiklar från Google News RSS med fallback till DDG News."""
  full_q = f"{query} {city}".strip() if city else query.strip()
  encoded_q = urllib.parse.quote(full_q)
  url = f"https://news.google.com/rss/search?q={encoded_q}&hl=sv&gl=SE&ceid=SE:sv"
  headers = {
      "User-Agent": (
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
      )
  }
  articles = []
  try:
    async with session.get(url, headers=headers, timeout=10) as resp:
      if resp.status == 200:
        xml_text = await resp.text()
        root = ET.fromstring(xml_text)
        for item in root.findall(".//item")[:max_items]:
          articles.append({
              "title": item.findtext("title", ""),
              "source": item.findtext("source", ""),
              "published": item.findtext("pubDate", ""),
              "url": item.findtext("link", ""),
          })
  except Exception:
    pass

  if not articles:
    try:
      time.sleep(0.8)
      with DDGS() as ddgs:
        news_res = list(
            ddgs.news(full_q, region="se-se", max_results=max_items)
        )
        for n in news_res:
          articles.append({
              "title": n.get("title", ""),
              "source": n.get("source", ""),
              "published": n.get("date", ""),
              "url": n.get("url", ""),
          })
    except Exception as e:
      return {"source": "google_news", "error": str(e), "articles": []}

  return {"source": "google_news", "query": full_q, "articles": articles}


def search_youtube_presence(
    query: str, city: str = "", max_results: int = 6
) -> dict:
  """Söker efter publika YouTube-videor med strikt domän- och relevanskontroll."""
  try:
    time.sleep(0.8)
    with DDGS() as ddgs:
      city_q = f'"{city}"' if city else ""
      q = f'"{query}" {city_q} site:youtube.com'
      raw = list(
          ddgs.text(
              q,
              region="se-se",
              safesearch="moderate",
              max_results=max_results,
          )
      )
      filtered = [
          r
          for r in raw
          if "youtube.com" in r.get("href", "").lower()
          and is_relevant_hit(r, query, city)
      ]
      return {"source": "youtube_osint", "query": q, "results": filtered}
  except Exception as e:
    return {"source": "youtube_osint", "error": str(e), "results": []}


def search_ddg(
    query: str,
    filter_target: str = "",
    city: str = "",
    max_results: int = 8,
    required_domain: str = "",
) -> dict:
  """Utför webbsökning i svensk region med strikt filtrering mot rate-limiting och skräp."""
  try:
    time.sleep(0.8)
    with DDGS() as ddgs:
      raw = list(
          ddgs.text(
              query,
              region="se-se",
              safesearch="moderate",
