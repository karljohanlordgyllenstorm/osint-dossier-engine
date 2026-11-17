import asyncio
from datetime import datetime, timezone
import re
import socket
import ssl
import time
from typing import Any, Dict, List
import urllib.parse
import xml.etree.ElementTree as ET
import aiohttp
from bs4 import BeautifulSoup
import dns.resolver
from duckduckgo_search import DDGS
import whois


def normalize_target_name(target: str) -> str:
  t = target.strip()
  if "ohlsson" in t.lower():
    t = re.sub(r"ohlsson", "ohlson", t, flags=re.IGNORECASE)
  return t


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


def get_correct_domain(target: str) -> str:
  t = target.lower().strip()
  mapping = {
      "skanska ab": "skanska.se",
      "skanska": "skanska.se",
      "peab ab": "peab.se",
      "peab": "peab.se",
      "clas ohlson ab": "clasohlson.com",
      "clas ohlson": "clasohlson.com",
      "lindab ab": "lindab.com",
      "lindab": "lindab.com",
  }
  for key, domain in mapping.items():
    if key in t:
      return domain
  clean = (
      t.replace("ab", "").replace("publ", "").replace(".", "").replace(" ", "")
  )
  return f"{clean}.se"


def extract_entities_from_news(
    articles: List[Dict[str, Any]], company_name: str = ""
) -> Dict[str, Any]:
  """
    Parsar titlar och eventuella sammanfattningar från insamlade nyhetsartiklar
    för att extrahera nyckelpersoner, rollreferenser (VD/ledning) och belopp/omsättning.
    """
  stopwords = {
      "Sverige",
      "Stockholm",
      "Göteborg",
      "Malmö",
      "Uppsala",
      "Norrköping",
      "Helsingborg",
      "Kristianstad",
      "Trelleborg",
      "Lund",
      "Partille",
      "Umeå",
      "Luleå",
      "Polen",
      "Warszawa",
      "Cision",
      "News",
      "Via",
      "Mynewsdesk",
      "Nyheter",
      "Affärsvärlden",
      "Dagens",
      "Industri",
      "Svenska",
      "Domstolen",
      "Forbes",
      "Axis",
      "Communications",
      "Skandia",
      "Fastigheter",
      "Industrivärden",
      "Volvo",
      "Mustaschkampen",
      "Safe",
      "International",
      "Steel",
      "Profil",
      "Byggpartner",
      "Anläggning",
      "Studio",
      "Sjöstaden",
      "Valberedning",
      "Halvårsrapport",
      "Delårsrapport",
      "Så",
      "Ny",
      "Nytt",
      "Därför",
      "Intäkten",
      "Intäkterna",
      "Negativt",
      "Blufföretag",
  }

  for part in company_name.replace("AB", "").split():
    stopwords.add(part.strip())

  financial_pattern = re.compile(
      r"((?:EUR|USD|SEK|kr)?\s*\d+(?:[.,]\d+)?\s*(?:miljoner|miljarder|mnkr|mdkr|msek|M|B)(?:\s*kronor)?)",
      re.IGNORECASE,
  )

  role_pattern = re.compile(
      r"\b(VD|verkställande direktör|koncernchef|styrelseordförande|ordförande|finanschef|CFO|CEO|valberedning|leder)\b",
      re.IGNORECASE,
  )

  name_pattern = re.compile(
      r"\b([A-ZÅÄÖ][a-zåäöéü-]{1,20}\s+[A-ZÅÄÖ][a-zåäöéü-]{1,25})\b"
  )

  extracted_people = []
  extracted_roles = []
  extracted_financials = []

  seen_people = set()
  seen_financials = set()

  for article in articles:
    title = article.get("title", "")
    description = article.get("description", "")
    clean_title = re.sub(r"\s+-\s+[^-]+$", "", title).strip()
    text_to_scan = (
        f"{clean_title}. {description}".strip() if description else clean_title
    )
    source = article.get("source", "")
    published = article.get("published", "")
    url = article.get("url", "")

    for match in financial_pattern.findall(text_to_scan):
      val = match.strip()
      key = f"{val}|{clean_title}"
      if key not in seen_financials:
        seen_financials.add(key)
        extracted_financials.append({
            "amount": val,
            "context": clean_title,
            "source": source,
            "published": published,
            "url": url,
        })

    role_matches = role_pattern.findall(text_to_scan)
    if role_matches:
      extracted_roles.append({
          "roles_mentioned": list(set(r.upper() for r in role_matches)),
          "context": clean_title,
          "source": source,
          "published": published,
          "url": url,
      })

    for candidate in name_pattern.findall(text_to_scan):
      parts = candidate.split()
      if not any(p in stopwords for p in parts):
        if candidate not in seen_people:
          seen_people.add(candidate)
          extracted_people.append({
              "name": candidate,
              "context": clean_title,
              "source": source,
              "published": published,
              "url": url,
          })

  return {
      "people": extracted_people,
      "executive_references": extracted_roles,
      "financial_mentions": extracted_financials,
  }


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
        return {"source": "crt.sh", "subdomains": sorted(list(subs))[:200]}
  except Exception as e:
    return {"source": "crt.sh", "error": str(e), "subdomains": []}
  return {"source": "crt.sh", "subdomains": []}


async def fetch_google_news(
    session: aiohttp.ClientSession, query: str, city: str = "", max_items: int = 12
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
          raw_desc = item.findtext("description", "")
          clean_desc = (
              BeautifulSoup(raw_desc, "html.parser").get_text(" ", strip=True)
              if raw_desc
              else ""
          )
          articles.append({
              "title": item.findtext("title", ""),
              "description": clean_desc,
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
              "description": n.get("body", ""),
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
  try:
    time.sleep(0.8)
    with DDGS() as ddgs:
      queries = [
          f"{company_name} årsredovisning omsättning resultat",
          f"{company_name} organisationsnummer styrelse VD",
          f"site:allabolag.se {company_name}",
      ]
      results = []
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
                q, region="se-se", safesearch="moderate", max_results=6
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
          f'"{name}" VD OR styrelseordförande OR koncernchef',
          f'"{name}" {city_query} site:linkedin.com/company/ OR site:linkedin.com/in/',
          f'"{name}" ledning styrelse medarbetare',
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
          "results": all_results[:15],
      }
  except Exception as e:
    return {"source": "person_osint", "error": str(e), "results": []}


async def collect_all_data(target: str, city: str = "") -> dict:
  target = normalize_target_name(target)
  info = classify_target(target)
  loop = asyncio.get_event_loop()
  results = {"target": info, "timestamp": datetime.now(timezone.utc).isoformat()}
  clean_domain = get_correct_domain(target)

  async with aiohttp.ClientSession(
      headers={"User-Agent": "OSINT-Legal-Engine/2.5"}
  ) as session:
    tasks = [
        fetch_company_business_data(session, target),
        fetch_google_news(session, target, city, max_items=12),
        fetch_crt_sh(session, clean_domain),
        loop.run_in_executor(
            None, fetch_public_diaries_and_properties, target, city
        ),
        loop.run_in_executor(
            None, fetch_person_socials_and_connections, target, city
        ),
        loop.run_in_executor(None, get_dns_records, clean_domain),
        loop.run_in_executor(None, get_whois_info, clean_domain),
    ]

    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    clean_gathered = [
        g if not isinstance(g, Exception) else {"source": "error", "error": str(g)}
        for g in gathered
    ]

    # Hämta insamlade nyhetsartiklar och parsa entiteter
    news_articles = []
    for item in clean_gathered:
      if item.get("source") == "google_news":
        news_articles = item.get("articles", [])
        break

    parsed_entities = extract_entities_from_news(
        news_articles, company_name=target
    )

    # Berika company_intelligence och person_osint med extraherade träffar från nyhetsflödet
    for item in clean_gathered:
      src = item.get("source")
      if src == "company_intelligence":
        item["parsed_financial_mentions"] = parsed_entities[
            "financial_mentions"
        ]
        for fin in parsed_entities["financial_mentions"]:
          item["results"].append({
              "title": f"Finansiell uppgift ({fin['amount']}): {fin['context']}",
              "href": fin["url"],
              "body": f"Källa: {fin['source']} ({fin['published']})",
          })
      elif src == "person_osint":
        item["parsed_people"] = parsed_entities["people"]
        item["parsed_executive_references"] = parsed_entities[
            "executive_references"
        ]
        for person in parsed_entities["people"]:
          item["results"].append({
              "title": f"Omnämnd person: {person['name']}",
              "href": person["url"],
              "body": f"{person['context']} — {person['source']} ({person['published']})",
          })
        for role in parsed_entities["executive_references"]:
          roles_str = ", ".join(role["roles_mentioned"])
          item["results"].append({
              "title": f"Ledningsreferens ({roles_str}): {role['context']}",
              "href": role["url"],
              "body": f"Källa: {role['source']} ({role['published']})",
          })

    clean_gathered.append({
        "source": "news_entity_extraction",
        "data": parsed_entities,
    })

    results["findings"] = clean_gathered

  return results
