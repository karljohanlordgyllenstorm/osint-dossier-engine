import asyncio
from datetime import datetime, timezone
import re
import socket
import ssl
import aiohttp
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


def search_ddg(query: str, max_results: int = 8) -> dict:
  try:
    with DDGS() as ddgs:
      results = list(ddgs.text(query, max_results=max_results))
      return {"source": "ddg_search", "query": query, "results": results}
  except Exception as e:
    return {"source": "ddg_search", "error": str(e), "results": []}


async def fetch_company_business_data(
    session: aiohttp.ClientSession, company_name: str
) -> dict:
  try:
    with DDGS() as ddgs:
      queries = [
          f'"{company_name}" site:allabolag.se OR site:ratsit.se OR site:proff.se',
          f'"{company_name}" omsättning resultat styrelse ägare',
      ]
      results = []
      for q in queries:
        res = list(ddgs.text(q, max_results=5))
        results.extend(res)
      return {
          "source": "company_intelligence",
          "query": company_name,
          "results": results,
      }
  except Exception as e:
    return {"source": "company_intelligence", "error": str(e), "results": []}


async def fetch_person_socials_and_location(
    session: aiohttp.ClientSession, name: str, city: str = ""
) -> dict:
  try:
    with DDGS() as ddgs:
      city_query = f'"{city}"' if city else ""
      queries = [
          f'"{name}" {city_query} site:linkedin.com/in/',
          f'"{name}" {city_query} site:github.com OR site:ratsit.se OR site:allabolag.se',
      ]

      all_results = []
      for q in queries:
        res = list(ddgs.text(q, max_results=6))
        for r in res:
          href = r.get("href", "").lower()
          # Filtrera bort vanliga skräpsajter som ger orelevanta träffar
          if "answers.com" in href or "calculateme.com" in href:
            continue
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
  info = classify_target(target)
  loop = asyncio.get_event_loop()
  results = {"target": info, "timestamp": datetime.now(timezone.utc).isoformat()}

  async with aiohttp.ClientSession(
      headers={"User-Agent": "OSINT-Dossier-Engine/1.1"}
  ) as session:
    tasks = []

    if info["type"] == "domain":
      domain = info["value"]
      tasks.append(fetch_crt_sh(session, domain))
      tasks.append(fetch_hackertarget_subs(session, domain))
      tasks.append(fetch_http_security_and_tech(session, domain))
      tasks.append(fetch_well_known_files(session, domain))
      tasks.append(fetch_urlhaus(session, domain))
      tasks.append(fetch_wayback(session, domain))
      tasks.append(loop.run_in_executor(None, get_dns_records, domain))
      tasks.append(loop.run_in_executor(None, get_whois_info, domain))
      tasks.append(loop.run_in_executor(None, get_ssl_info, domain))
      tasks.append(loop.run_in_executor(None, search_ddg, f"site:{domain}", 10))
      tasks.append(
          loop.run_in_executor(
              None,
              search_ddg,
              f"site:{domain} filetype:pdf OR filetype:xlsx OR filetype:docx",
              8,
          )
      )
      tasks.append(
          loop.run_in_executor(
              None, search_ddg, f'"@{domain}" OR "{domain}" email', 8
          )
      )

      try:
        ip = socket.gethostbyname(domain)
        results["resolved_ip"] = ip
        tasks.append(fetch_internetdb(session, ip))
        tasks.append(fetch_ip_geo_and_asn(session, ip))
      except socket.gaierror:
        results["resolved_ip"] = None

    elif info["type"] == "ip":
      ip = info["value"]
      tasks.append(fetch_internetdb(session, ip))
      tasks.append(fetch_ip_geo_and_asn(session, ip))
      tasks.append(fetch_urlhaus(session, ip))
      tasks.append(loop.run_in_executor(None, search_ddg, f'"{ip}"', 10))

    elif info["type"] == "organization":
      org_val = info["value"]
      tasks.append(fetch_company_business_data(session, org_val))
      tasks.append(
          loop.run_in_executor(
              None,
              search_ddg,
              f'"{org_val}" site:allabolag.se OR site:ratsit.se OR site:proff.se',
              10,
          )
      )
      tasks.append(
          loop.run_in_executor(
              None, search_ddg, f'"{org_val}" styrelse OR ägare OR omsättning', 8
          )
      )

    else:  # person
      person_val = info["value"]
      tasks.append(
          fetch_person_socials_and_location(session, person_val, city)
      )
      city_str = f'"{city}"' if city else ""
      tasks.append(
          loop.run_in_executor(
              None,
              search_ddg,
              f'"{person_val}" {city_str} site:linkedin.com/in/',
              10,
          )
      )
      tasks.append(
          loop.run_in_executor(
              None,
              search_ddg,
              f'"{person_val}" {city_str} ratsit OR merinfo OR eniro',
              8,
          )
      )

    gathered = await asyncio.gather(*tasks)
    results["findings"] = gathered

  return results
