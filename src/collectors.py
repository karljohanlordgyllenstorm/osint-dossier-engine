import asyncio
from datetime import datetime, timezone
import re
from typing import Any, Dict, List
import urllib.parse
import xml.etree.ElementTree as ET
import aiohttp
from bs4 import BeautifulSoup
import dns.resolver
import whois

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "sv-SE,sv;q=0.9,en;q=0.8",
}


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

    clean = re.sub(r"\b(ab|publ|aktiebolag)\b", "", t)
    clean = clean.translate(str.maketrans("åäöéü", "aaoeu"))
    clean = re.sub(r"[^a-z0-9-]", "", clean)
    return f"{clean}.se"


def parse_allabolag_structured_block(body_text: str) -> List[Dict[str, Any]]:
    companies = []
    chunks = re.split(r"(?=[A-ZÅÄÖa-zåäö\s,-]+AB\s+(?:Org\.nr|Stockholm|Förslöv))", body_text)
    
    for chunk in chunks:
        org_match = re.search(r"\b(55\d{4}-\d{4}|212000-\d{4})\b", chunk)
        if not org_match:
            continue
            
        org_nr = org_match.group(1)
        name_match = re.search(r"([A-ZÅÄÖ][A-Za-zåäöÅÄÖ\s,-]+AB)", chunk)
        raw_name = name_match.group(1).strip() if name_match else "Bolag"
        
        rev_match = re.search(r"Omsättning\s+\d{4}\s+([\d\s]+)", chunk)
        revenue = rev_match.group(1).strip() if rev_match else None
        
        emp_match = re.search(r"Anställda\s+(\d+)", chunk)
        employees = emp_match.group(1) if emp_match else None
        
        vd_match = re.search(r"(?:Extern verkställande direktör|Verkställande direktör)\s+([A-ZÅÄÖa-zåäö\s]+?)(?=\s+(?:Byggmästare|VVS|Entreprenörer|Järnväg|Betong|Fastighetsbolag|IT|Datacenters|Jämför|Bevaka|Hitta)|$)", chunk)
        vd = vd_match.group(1).strip() if vd_match else None
        
        companies.append({
            "name": raw_name,
            "org_number": org_nr,
            "revenue_2025": revenue,
            "employees": employees,
            "ceo": vd
        })
        
    return companies


def extract_entities_from_texts(
    items: List[Dict[str, Any]], company_name: str = ""
) -> Dict[str, Any]:
    stopwords = {
        "Sverige", "Sweden", "Stockholm", "Göteborg", "Malmö", "Uppsala",
        "Norrköping", "Helsingborg", "Kristianstad", "Trelleborg", "Lund",
        "Partille", "Umeå", "Luleå", "Falun", "Köping", "Västerås",
        "Oskarshamn", "Botkyrka", "Lillänge", "Överby", "Polen", "Warszawa",
        "Cision", "News", "Via", "Mynewsdesk", "Nyheter", "Affärsvärlden",
        "Dagens", "Industri", "Svenska", "Domstolen", "Forbes", "Axis",
        "Communications", "Skandia", "Fastigheter", "Industrivärden", "Volvo",
        "Mustaschkampen", "Safe", "International", "Steel", "Profil",
        "Byggpartner", "Anläggning", "Studio", "Sjöstaden", "Valberedning",
        "Halvårsrapport", "Delårsrapport", "Så", "Ny", "Nytt", "Nya",
        "Därför", "Intäkten", "Intäkterna", "Negativt", "Blufföretag",
        "Allabolag", "Merinfo", "Ratsit", "Bolagsverket", "Uppgifter",
        "Bokslut", "Nyckeltal", "Styrelse", "Befattningshavare", "Verksamhet",
        "Kommun", "Omsorg", "Socialchef", "Black", "Friday", "Real", "Estate",
        "Tidningen", "Kuriren", "Wermlands", "Konsumentverket", "Ett", "Svidande",
        "Warfvinges", "Väg", "Industrial", "Solutions", "Slussen", "Construction",
        # Titlar som inte ska bli personer
        "Executive", "Vice", "President", "Sustainability", "Innovation", "Senior",
        # UI-skräp
        "Sök", "Välj", "Segmentering", "Jämför", "Nätverkssökning", "Konkurser",
        "Topplistor", "Mer", "Sortering", "Relevans", "Bevaka", "Hitta",
        "Branschöversikt", "Produkter", "Logga", "Företag", "Hela", "Län"
    }

    for part in re.sub(r"\b(AB|Aktiebolag)\b", "", company_name, flags=re.I).split():
        stopwords.add(part.strip().capitalize())

    org_nr_pattern = re.compile(r"\b(55\d{4}-\d{4}|212000-\d{4})\b")
    financial_pattern = re.compile(
        r"((?:EUR|USD|SEK|kr)?\s*\d+(?:[.,]\d+)?\s*(?:miljoner|miljarder|mnkr|mdkr|msek|tkr)(?:\s*kronor)?)",
        re.IGNORECASE,
    )
    role_pattern = re.compile(
        r"\b(VD|verkställande direktör|koncernchef|styrelseordförande|ordförande|finanschef|CFO|CEO|valberedning|socialchef|Executive Vice President|Senior Vice President)\b",
        re.IGNORECASE,
    )
    name_pattern = re.compile(
        r"\b([A-ZÅÄÖ][a-zåäöéü]{2,20}\s+[A-ZÅÄÖ][a-zåäöéü]{2,25})\b"
    )

    extracted_org_nrs = set()
    extracted_people = []
    extracted_roles = []
    extracted_financials = []

    seen_people = set()
    seen_financials = set()

    for item in items:
        if item.get("source") == "company_intelligence":
            body_text = item.get("body", "")
            for org_match in org_nr_pattern.findall(body_text):
                extracted_org_nrs.add(org_match)
            continue

        title = item.get("title", "")
        source = item.get("source", "")
        published = item.get("published", "")
        url = item.get("url") or item.get("href", "")

        clean_title = re.sub(r"\s+-\s+[^-]+$", "", title).strip()
        raw_desc = item.get("description") or item.get("body", "")

        if raw_desc and clean_title in raw_desc and len(raw_desc) <= len(title) + 10:
            text_to_scan = clean_title
        else:
            text_to_scan = f"{clean_title}. {raw_desc}".strip() if raw_desc else clean_title

        source_words = set(re.findall(r"[A-ZÅÄÖ][a-zåäöéü]+", source))

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
            if any(p in stopwords or p in source_words for p in parts):
                continue
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
    full_q = f'"{query}" {city}'.strip() if city else f'"{query}"'
    encoded_q = urllib.parse.quote(full_q)
    url = f"https://news.google.com/rss/search?q={encoded_q}&hl=sv&gl=SE&ceid=SE:sv"
    articles = []
    try:
        async with session.get(url, headers=BROWSER_HEADERS, timeout=10) as resp:
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


async def fetch_wikidata_company(
    session: aiohttp.ClientSession, company_name: str
) -> Dict[str, Any]:
    clean_name = re.sub(r"\b(AB|Aktiebolag)\b", "", company_name, flags=re.I).strip()
    search_url = (
        "https://www.wikidata.org/w/api.php"
        f"?action=wbsearchentities&search={urllib.parse.quote(clean_name)}"
        "&language=sv&format=json&limit=3"
    )
    info: Dict[str, Any] = {}
    try:
        async with session.get(search_url, timeout=10) as resp:
            if resp.status != 200:
                return info
            data = await resp.json()
            hits = data.get("search", [])
            if not hits:
                return info

            entity_id = hits[0]["id"]
            info["wikidata_id"] = entity_id
            info["description"] = hits[0].get("description", "")

            entity_url = f"https://www.wikidata.org/wiki/Special:EntityData/{entity_id}.json"
            async with session.get(entity_url, timeout=10) as eresp:
                if eresp.status == 200:
                    edata = await eresp.json()
                    claims = edata.get("entities", {}).get(entity_id, {}).get("claims", {})

                    if "P856" in claims:
                        raw_url = claims["P856"][0]["mainsnak"]["datavalue"]["value"]
                        info["official_website"] = raw_url
                    if "P1128" in claims:
                        info["employees"] = claims["P1128"][0]["mainsnak"]["datavalue"]["value"].get("amount", "").lstrip("+")
                    if "P571" in claims:
                        info["inception"] = claims["P571"][0]["mainsnak"]["datavalue"]["value"].get("time", "")[:11].lstrip("+")
    except Exception:
        pass
    return info


async def fetch_allabolag_direct(
    session: aiohttp.ClientSession, company_name: str
) -> List[Dict[str, Any]]:
    encoded = urllib.parse.quote(company_name)
    url = f"https://www.allabolag.se/what/{encoded}"
    results = []
    try:
        async with session.get(url, headers=BROWSER_HEADERS, timeout=12) as resp:
            if resp.status == 200:
                html = await resp.text()
                soup = BeautifulSoup(html, "html.parser")
                text = soup.get_text(" ", strip=True)

                org_matches = re.findall(r"\b(55\d{4}-\d{4})\b", text)
                structured_subs = parse_allabolag_structured_block(text)
                
                if org_matches:
                    results.append({
                        "source": "company_intelligence",
                        "title": f"Allabolag träff för {company_name}",
                        "href": url,
                        "body": text[:1500],
                        "matched_org_numbers": list(dict.fromkeys(org_matches)),
                        "structured_subs": structured_subs,
                    })
    except Exception:
        pass
    return results


async def fetch_company_business_data(
    session: aiohttp.ClientSession, company_name: str
) -> dict:
    wikidata_info, allabolag_hits = await asyncio.gather(
        fetch_wikidata_company(session, company_name),
        fetch_allabolag_direct(session, company_name),
    )

    results = list(allabolag_hits)
    if wikidata_info:
        results.append({
            "source": "company_intelligence",
            "title": f"Wikidata: {company_name}",
            "href": f"https://www.wikidata.org/wiki/{wikidata_info.get('wikidata_id', '')}",
            "body": str(wikidata_info),
            "structured": wikidata_info,
        })

    return {
        "source": "company_intelligence",
        "query": company_name,
        "wikidata": wikidata_info,
        "results": results,
    }


async def fetch_public_diaries_and_properties(
    session: aiohttp.ClientSession, target_name: str, city: str = "", org_nr: str = ""
) -> dict:
    id_part = f' OR "{org_nr}"' if org_nr else ""
    queries = [
        f'"{target_name}"{id_part} (tillsyn OR beslut OR domstol OR polisanmäl* OR misskötsel)',
        f'"{target_name}"{id_part} (Konsumentverket OR IVO OR Arbetsmiljöverket OR Konkurrensverket)'
    ]
    
    all_articles = []
    for q in queries:
        res = await fetch_google_news(session, q, city="", max_items=5)
        all_articles.extend(res.get("articles", []))
        
    unique_articles = {a["url"]: a for a in all_articles}.values()

    return {
        "source": "public_diaries_properties",
        "queries_used": queries,
        "results": list(unique_articles),
    }


async def fetch_person_socials_and_connections(
    session: aiohttp.ClientSession,
    company_name: str,
    discovered_people: List[str],
    city: str = "",
) -> dict:
    query = f'"{company_name}" (VD OR styrelseordförande OR koncernchef OR grundare)'
    exec_news = await fetch_google_news(session, query, city=city, max_items=8)

    results = list(exec_news.get("articles", []))
    for person in discovered_people[:3]:
        p_news = await fetch_google_news(session, f'"{person}" "{company_name}"', max_items=4)
        results.extend(p_news.get("articles", []))

    return {
        "source": "person_osint",
        "target_company": company_name,
        "queried_people": discovered_people[:3],
        "city": city,
        "results": results[:15],
    }


def generate_markdown_report(data: dict) -> str:
    target_info = data.get("target", {})
    identifiers = data.get("resolved_identifiers", {})
    findings = data.get("findings", [])
    
    company_name = target_info.get("value", "Okänt bolag")
    org_nr = identifiers.get("org_number", "Ej tillgängligt")
    domain = identifiers.get("domain", "Ej tillgängligt")
    people = identifiers.get("discovered_people", [])
    
    financials = []
    structured_subs = []
    regulatory_articles = []
    
    for f in findings:
        if "parsed_financial_mentions" in f:
            financials.extend(f["parsed_financial_mentions"])
        for r in f.get("results", []):
            if "structured_subs" in r:
                structured_subs.extend(r["structured_subs"])
        if f.get("source") == "public_diaries_properties":
            regulatory_articles.extend(f.get("results", []))

    report = []
    report.append(f"# Bakgrunds- och Due Diligence-rapport: {company_name}\n")
    report.append(f"* **Genererad:** {data.get('timestamp')}")
    report.append(f"* **Organisationsnummer:** `{org_nr}`")
    report.append(f"* **Huvuddomän:** `{domain}`\n")
    
    report.append("---")
    report.append("## 1. Koncern- och Bolagsstruktur")
    if structured_subs:
        report.append("Följande enheter hittades via Allabolag:")
        report.append("| Bolagsnamn | Org.nr | Omsättning (senaste) | Anställda | VD / Chef |")
        report.append("| :--- | :--- | :--- | :--- | :--- |")
        for sub in structured_subs:
            report.append(f"| {sub.get('name')} | `{sub.get('org_number')}` | {sub.get('revenue_2025', '-')} | {sub.get('employees', '-')} | {sub.get('ceo', '-')} |")
    else:
        report.append("Inga strukturerade dotterbolagsdetaljer kunde extraheras.")
        
    report.append("\n---")
    report.append("## 2. Ekonomi & Större Affärer")
    if financials:
        report.append("Relevanta finansiella transaktioner och projekt som hittades i nyhetsflödet:")
        for fin in financials[:5]:
            report.append(f"- **{fin.get('amount')}**: {fin.get('context')} (*Källa: {fin.get('source')}*)")
    else:
        report.append("Inga specifika finansiella belopp noterades.")

    report.append("\n---")
    report.append("## 3. Tillsyn, Juridik & Myndighetsärenden")
    if regulatory_articles:
        report.append("Händelser eller artiklar rörande tillsyn, beslut eller tvister:")
        for reg in regulatory_articles[:5]:
            report.append(f"- [{reg.get('title')}]({reg.get('url')}) - *{reg.get('source')}*")
    else:
        report.append("Inga direkta tillsyns- eller myndighetsärenden matchade sökningen.")

    report.append("\n---")
    report.append("## 4. Nyckelpersoner")
    if people:
        report.append("Uppmärksammade personer kopplade till bolaget i nyhetsrapporteringen:")
        for p in people[:10]:
            report.append(f"- {p}")
    else:
        report.append("Inga externa nyckelpersoner extraherades.")

    return "\n".join(report)


async def collect_all_data(target: str, city: str = "") -> dict:
    target = normalize_target_name(target)
    info = classify_target(target)
    city = city.strip()

    loop = asyncio.get_running_loop()
    results = {
        "target": info,
        "city": city or None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    async with aiohttp.ClientSession(headers=BROWSER_HEADERS) as session:
        company_data, news_data = await asyncio.gather(
            fetch_company_business_data(session, target),
            fetch_google_news(session, target, city=city, max_items=12),
        )

        combined_texts = company_data.get("results", []) + news_data.get("articles", [])
        parsed_entities = extract_entities_from_texts(combined_texts, company_name=target)

        direct_orgs = []
        for r in company_data.get("results", []):
            direct_orgs.extend(r.get("matched_org_numbers", []))
        all_orgs = list(dict.fromkeys(direct_orgs + parsed_entities["org_numbers"]))
        parsed_entities["org_numbers"] = all_orgs
        org_nr = all_orgs[0] if all_orgs else ""

        wikidata_site = company_data.get("wikidata", {}).get("official_website", "")
        if wikidata_site:
            resolved_domain = urllib.parse.urlparse(wikidata_site).netloc.lower().removeprefix("www.")
        else:
            resolved_domain = get_correct_domain(target)

        discovered_names = [p["name"] for p in parsed_entities["people"]]

        results["resolved_identifiers"] = {
            "org_number": org_nr or None,
            "domain": resolved_domain,
            "discovered_people": discovered_names,
        }

        tasks = [
            fetch_crt_sh(session, resolved_domain),
            fetch_public_diaries_and_properties(session, target, city=city, org_nr=org_nr),
            fetch_person_socials_and_connections(session, target, discovered_names, city=city),
            loop.run_in_executor(None, get_dns_records, resolved_domain),
            loop.run_in_executor(None, get_whois_info, resolved_domain),
        ]

        step2_gathered = await asyncio.gather(*tasks, return_exceptions=True)
        clean_step2 = [
            g if not isinstance(g, Exception) else {"source": "error", "error": str(g)}
            for g in step2_gathered
        ]

        company_data["org_numbers"] = all_orgs
        company_data["parsed_financial_mentions"] = parsed_entities["financial_mentions"]

        for item in clean_step2:
            if item.get("source") == "person_osint":
                item["parsed_people"] = parsed_entities["people"]
                item["parsed_executive_references"] = parsed_entities["executive_references"]

        all_findings = [company_data, news_data] + clean_step2 + [
            {
                "source": "entity_extraction",
                "data": parsed_entities,
            }
        ]

        results["findings"] = all_findings
        results["markdown_report"] = generate_markdown_report(results)

    return results
