import asyncio
from datetime import datetime, timezone
import re
from typing import Any, Dict, List
import urllib.parse
import xml.etree.ElementTree as ET
import aiohttp
from bs4 import BeautifulSoup
import dns.resolver
from duckduckgo_search import DDGS
import whois

# Gemensam semafor för att förhindra att DDGS blockerar pga för många samtidiga anrop
DDGS_SEMAPHORE = asyncio.Semaphore(1)


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

    # Ta bort bolagsformer och översätt svenska tecken till ASCII
    clean = re.sub(r"\b(ab|publ|aktiebolag)\b", "", t)
    clean = clean.translate(str.maketrans("åäöéü", "aaoeu"))
    clean = re.sub(r"[^a-z0-9-]", "", clean)
    return f"{clean}.se"


async def safe_ddgs_text(query: str, max_results: int = 6) -> List[Dict[str, Any]]:
    """Kör DDGS-sökningar sekventiellt med fördröjning för att undvika tyst rate-limiting."""
    async with DDGS_SEMAPHORE:
        await asyncio.sleep(2.2)
        loop = asyncio.get_running_loop()

        def _search():
            with DDGS() as ddgs:
                return list(
                    ddgs.text(
                        query,
                        region="se-se",
                        safesearch="moderate",
                        max_results=max_results,
                    )
                )

        try:
            return await loop.run_in_executor(None, _search)
        except Exception:
            return []


def extract_entities_from_texts(
    items: List[Dict[str, Any]], company_name: str = ""
) -> Dict[str, Any]:
    """
    Parsar titlar och sammanfattningar från både nyheter och sökresultat
    för att extrahera organisationsnummer, nyckelpersoner, roller och belopp.
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
        "Allabolag",
        "Merinfo",
        "Ratsit",
        "Bolagsverket",
        "Uppgifter",
        "Bokslut",
        "Nyckeltal",
        "Styrelse",
        "Befattningshavare",
        "Verksamhet",
        "Kommun",
        "Omsorg",
        "Socialchef",
    }

    for part in re.sub(r"\b(AB|Aktiebolag)\b", "", company_name, flags=re.I).split():
        stopwords.add(part.strip().capitalize())

    org_nr_pattern = re.compile(r"\b(55\d{4}-\d{4}|212000-\d{4})\b")
    financial_pattern = re.compile(
        r"((?:EUR|USD|SEK|kr)?\s*\d+(?:[.,]\d+)?\s*(?:miljoner|miljarder|mnkr|mdkr|msek|tkr|M|B)(?:\s*kronor)?)",
        re.IGNORECASE,
    )
    role_pattern = re.compile(
        r"\b(VD|verkställande direktör|koncernchef|styrelseordförande|ordförande|finanschef|CFO|CEO|valberedning|socialchef)\b",
        re.IGNORECASE,
    )
    name_pattern = re.compile(
        r"\b([A-ZÅÄÖ][a-zåäöéü-]{1,20}\s+[A-ZÅÄÖ][a-zåäöéü-]{1,25})\b"
    )

    extracted_org_nrs = set()
    extracted_people = []
    extracted_roles = []
    extracted_financials = []

    seen_people = set()
    seen_financials = set()

    for item in items:
        title = item.get("title", "")
        description = item.get("description") or item.get("body", "")
        clean_title = re.sub(r"\s+-\s+[^-]+$", "", title).strip()
        text_to_scan = (
            f"{clean_title}. {description}".strip() if description else clean_title
        )
        source = item.get("source", "Webb")
        published = item.get("published", "")
        url = item.get("url") or item.get("href", "")

        for org_match in org_nr_pattern.findall(text_to_scan):
            extracted_org_nrs.add(org_match)

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
        "org_numbers": sorted(list(extracted_org_nrs)),
        "people": extracted_people,
        "executive_references": extracted_roles,
        "financial_mentions": extracted_financials,
    }


def detect_official_domain(
    search_results: List[Dict[str, Any]], fallback_domain: str
) -> str:
    """Försöker hitta bolagets faktiska webbplats i sökresultaten innan WHOIS/DNS körs."""
    ignored_hosts = {
        "allabolag.se",
        "ratsit.se",
        "merinfo.se",
        "hitta.se",
        "eniro.se",
        "proff.se",
        "bolagsfakta.se",
        "linkedin.com",
        "facebook.com",
        "wikipedia.org",
        "hd.se",
        "dagenssamhalle.se",
        "dagensmedicin.se",
        "duckduckgo.com",
    }
    for r in search_results:
        href = r.get("href", "")
        if not href:
            continue
        parsed = urllib.parse.urlparse(href)
        host = parsed.netloc.lower().removeprefix("www.")
        if host and not any(ig in host for ig in ignored_hosts):
            if host.endswith((".se", ".com", ".nu", ".org")):
                return host
    return fallback_domain


def get_dns_records(domain: str) -> dict:
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CAA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [r.to_text().strip('"') for r in answers]
        except Exception:
            records[rtype] = []
    return {"source": "dns", "domain": domain, "data": records}


def get_whois_info(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        return {
            "source": "whois",
            "domain": domain,
            "data": {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "org": w.org,
                "country": w.country,
            },
        }
    except Exception as e:
        return {"source": "whois", "domain": domain, "error": str(e), "data": {}}


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
                return {
                    "source": "crt.sh",
                    "domain": domain,
                    "subdomains": sorted(list(subs))[:200],
                }
    except Exception as e:
        return {
            "source": "crt.sh",
            "domain": domain,
            "error": str(e),
            "subdomains": [],
        }
    return {"source": "crt.sh", "domain": domain, "subdomains": []}


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

    return {"source": "google_news", "query": full_q, "articles": articles}


async def fetch_company_business_data(company_name: str) -> dict:
    queries = [
        f'"{company_name}" site:allabolag.se OR site:merinfo.se OR site:ratsit.se',
        f'"{company_name}" organisationsnummer styrelse VD omsättning',
        f'"{company_name}" hemsida kontakt',
    ]
    results = []
    seen_urls = set()

    for q in queries:
        res = await safe_ddgs_text(q, max_results=6)
        for r in res:
            href = r.get("href", "")
            if href and href not in seen_urls:
                seen_urls.add(href)
                results.append(r)

    return {
        "source": "company_intelligence",
        "query": company_name,
        "results": results,
    }


async def fetch_public_diaries_and_properties(
    target_name: str, city: str = "", org_nr: str = ""
) -> dict:
    city_q = f'"{city}"' if city else ""
    id_q = f'OR "{org_nr}"' if org_nr else ""
    queries = [
        f'"{target_name}" {id_q} {city_q} diarium OR beslut OR tillsyn OR IVO',
        f'"{target_name}" {city_q} fastighet OR lagfart OR upphandling',
    ]
    results = []
    seen = set()

    for q in queries:
        res = await safe_ddgs_text(q, max_results=6)
        for r in res:
            href = r.get("href", "")
            if href and href not in seen:
                seen.add(href)
                results.append(r)

    return {
        "source": "public_diaries_properties",
        "query": target_name,
        "city": city,
        "results": results[:12],
    }


async def fetch_person_socials_and_connections(
    company_name: str, discovered_people: List[str], city: str = ""
) -> dict:
    city_query = f'"{city}"' if city else ""
    queries = [
        f'"{company_name}" VD OR styrelseordförande OR styrelseledamot',
        f'"{company_name}" {city_query} site:linkedin.com/company/ OR site:linkedin.com/in/',
    ]

    # Lägg till riktade sökningar på faktiska personer som hittats i Steg 1
    for person in discovered_people[:3]:
        queries.append(f'"{person}" "{company_name}" OR {city_query}'.strip())

    all_results = []
    seen_urls = set()

    for q in queries:
        res = await safe_ddgs_text(q, max_results=5)
        for r in res:
            href = r.get("href", "")
            if href and href not in seen_urls:
                seen_urls.add(href)
                all_results.append(r)

    return {
        "source": "person_osint",
        "target_company": company_name,
        "queried_people": discovered_people[:3],
        "city": city,
        "results": all_results[:15],
    }


async def collect_all_data(target: str, city: str = "") -> dict:
    target = normalize_target_name(target)
    info = classify_target(target)

    # Försök extrahera stad automatiskt ur bolagsnamnet om city inte angivits
    if not city and info["type"] == "organization":
        first_word = target.split()[0]
        if first_word.lower() not in {"ab", "svenska", "nordiska", "nya"}:
            city = first_word

    loop = asyncio.get_running_loop()
    results = {
        "target": info,
        "inferred_city": city,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    async with aiohttp.ClientSession(
        headers={"User-Agent": "OSINT-Legal-Engine/2.6"}
    ) as session:
        # STEG 1: Hämta grundläggande företagsdata & nyheter först för identitetsupplösning
        company_data, news_data = await asyncio.gather(
            fetch_
