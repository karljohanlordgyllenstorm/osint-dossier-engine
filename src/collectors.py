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
  """Tillåtande filtrering för att inte missa företagsrelaterade artiklar."""
  href = result.get("href", "").lower()
  spam_domains = [
      "answers.com",
      "calculateme.com",
      "salarycalculator.info",
      "savvydollar.com",
      "pinterest.",
      "amazon.com",
      "yelp.com",
      "tripadvisor.com",
  ]
  if any(sd in href for sd in spam_domains):
    return False
  return True


def get_dns_records(domain: str) -> dict:
  records = {}
  for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CAA"]:
    try:
      answers = dns.resolver.resolve(domain, rtype, lifetime=5)
      records[rtype] = [r.to_text().strip('"') for r in answers]
    except Exception:
      records[rtype] = []
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
            "org": w.org,
            "country": w.country,
        },
    }
  except Exception as e:
    return {"source": "whois", "error": str(e), "data": {}}


async def fetch_google_news(
    session: aiohttp.ClientSession, query: str, city: str = "", max_items: int = 10
) -> dict:
  full_q = f"{query} {city}".strip() if city else query.strip()
  encoded_q = urllib.parse.quote(full_q)
  url = f"https://news.google.com/rss/search?q={encoded_q}&hl=sv&gl=SE&ceid=SE:sv"
  headers = {
      "User-Agent": (
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
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


async def fetch_company_business_data(
    session: aiohttp.ClientSession, company_name: str
) -> dict:
  """Utökad bolagssökning som fångar upp allabolag, proff och finansiella nyckeltal."""
  try:
    with DDGS() as ddgs:
      queries = [
          f'"{company_name}" site:allabolag.se OR site:proff.se OR site:bolagsfakta.se',
          f'"{company_name}" bokslut OR omsättning OR resultat OR styrelse OR VD',
      ]
      results = []
      seen_urls = set()
      for q in queries:
        time.sleep(0.8)
        res = list(
            ddgs.text(
                q, region="se-se", safesearch="moderate", max_results=8
            )
        )
        for r in res:
          href = r.get("href", "")
          if href not in seen_urls:
            seen_urls.add(href)
            results.append(r)
      return {
          "source": "company_intelligence",
          "query": company_name,
          "results": results,
      }
  except Exception as e:
    return {"source": "company_intelligence", "error": str(e), "results": []}


def fetch_public_diaries_and_properties(
    target_name: str, city: str = ""
) -> dict:
  try:
    time.sleep(0.8)
    with DDGS() as ddgs:
      city_q = f'"{city}"' if city else ""
      queries = [
          f'"{target_name}" {city_q} diarium OR beslut OR ärende filetype:pdf',
          f'"{target_name}" {city_q} fastighet OR lagfart OR tomträtt',
      ]
      results = []
      seen = set()
      for q in queries:
        time.sleep(0.8)
        res = list(
            ddgs.text(
                q, region="se-se", safesearch="moderate", max_results=5
            )
        )
        for r in res:
          href = r.get("href", "")
          if href not in seen:
            seen.add(href)
            results.append(r)
      return {
          "source": "public_diaries_properties",
          "query": target_name,
          "city": city,
          "results": results[:12],
      }
  except Exception as e:
    return {
        "source": "public_diaries_properties",
        "error": str(e),
        "results": [],
    }


def fetch_person_socials_and_connections(name: str, city: str = "") -> dict:
  try:
    time.sleep(0.8)
    with DDGS() as ddgs:
      city_query = f'"{city}"' if city else ""
      queries = [
          f'"{name}" {city_query} site:linkedin.com/in/ OR site:linkedin.com/company/',
          f'"{name}" {city_query} site:instagram.com OR site:x.com OR site:facebook.com',
          f'"{name}" {city_query} styrelse OR VD OR grundare OR befattning',
      ]
      all_results = []
      seen_urls = set()
      for q in queries:
        time.sleep(0.8)
        res = list(
            ddgs.text(
                q, region="se-se", safesearch="moderate", max_results=6
            )
        )
        for r in res:
          href = r.get("href", "")
          if href not in seen_urls:
            seen_urls.add(href)
            all_results.append(r)
      return {
          "source": "person_osint",
          "target_name": name,
          "city": city,
          "results": all_results[:18],
      }
  except Exception as e:
    return {"source": "person_osint", "error": str(e), "results": []}


async def collect_all_data(target: str, city: str = "") -> dict:
  info = classify_target(target)
  loop = asyncio.get_event_loop()
  results = {"target": info, "timestamp": datetime.now(timezone.utc).isoformat()}

  async with aiohttp.ClientSession(
      headers={"User-Agent": "OSINT-Legal-Engine/2.0"}
  ) as session:
    tasks = []

    if info["type"] == "organization":
      org_val = info["value"]
      tasks.append(fetch_company_business_data(session, org_val))
      tasks.append(fetch_google_news(session, org_val, city, max_items=10))
      tasks.append(
          loop.run_in_executor(
              None, fetch_public_diaries_and_properties, org_val, city
          )
      )
      tasks.append(
          loop.run_in_executor(
              None, fetch_person_socials_and_connections, org_val, city
          )
      )
    else:
      val = info["value"]
      tasks.append(
          loop.run_in_executor(
              None, fetch_person_socials_and_connections, val, city
          )
      )
      tasks.append(fetch_google_news(session, val, city, max_items=10))

    gathered = await asyncio.gather(*tasks)
    results["findings"] = gathered

  return results
