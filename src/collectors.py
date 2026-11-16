import asyncio
from datetime import datetime
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
      s in target.lower() for s in ["ab", "inc", "corp", "ltd", "gmbh", "llc"]
  ):
    return {"type": "organization", "value": target}
  return {"type": "person", "value": target}


def get_dns_records(domain: str) -> dict:
  records = {}
  for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
    try:
      answers = dns.resolver.resolve(domain, rtype, lifetime=5)
      records[rtype] = [r.to_text().strip('"') for r in answers]
    except Exception:
      records[rtype] = []

  # Kontrollera DMARC
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
        return {
            "source": "ssl",
            "data": {
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notAfter": cert.get("notAfter"),
                "notBefore": cert.get("notBefore"),
            },
        }
  except Exception as e:
    return {"source": "ssl", "error": str(e), "data": {}}


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
        return {"source": "crt.sh", "subdomains": sorted(list(subs))[:100]}
  except Exception as e:
    return {"source": "crt.sh", "error": str(e), "subdomains": []}
  return {"source": "crt.sh", "subdomains": []}


async def fetch_internetdb(session: aiohttp.ClientSession, ip: str) -> dict:
  url = f"https://internetdb.shodan.io/{ip}"
  try:
    async with session.get(url, timeout=10) as resp:
      if resp.status == 200:
        return {"source": "internetdb", "data": await resp.json()}
  except Exception as e:
    return {"source": "internetdb", "error": str(e), "data": {}}
  return {"source": "internetdb", "data": {}}


async def fetch_ip_geo(session: aiohttp.ClientSession, ip: str) -> dict:
  url = f"http://ip-api.com/json/{ip}"
  try:
    async with session.get(url, timeout=10) as resp:
      if resp.status == 200:
        return {"source": "ip_geo", "data": await resp.json()}
  except Exception as e:
    return {"source": "ip_geo", "error": str(e), "data": {}}
  return {"source": "ip_geo", "data": {}}


async def fetch_wayback(session: aiohttp.ClientSession, domain: str) -> dict:
  url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=30"
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


async def collect_all_data(target: str) -> dict:
  info = classify_target(target)
  loop = asyncio.get_event_loop()
  results = {"target": info, "timestamp": datetime.utcnow().isoformat()}

  async with aiohttp.ClientSession(
      headers={"User-Agent": "OSINT-Dossier-Engine/1.0"}
  ) as session:
    tasks = []

    if info["type"] == "domain":
      domain = info["value"]
      tasks.append(fetch_crt_sh(session, domain))
      tasks.append(fetch_wayback(session, domain))
      tasks.append(loop.run_in_executor(None, get_dns_records, domain))
      tasks.append(loop.run_in_executor(None, get_whois_info, domain))
      tasks.append(loop.run_in_executor(None, get_ssl_info, domain))
      tasks.append(
          loop.run_in_executor(None, search_ddg, f'"{domain}" OR site:{domain}')
      )
      tasks.append(
          loop.run_in_executor(
              None,
              search_ddg,
              f'site:github.com "{domain}" OR "{domain}" password OR leak',
          )
      )

      try:
        ip = socket.gethostbyname(domain)
        results["resolved_ip"] = ip
        tasks.append(fetch_internetdb(session, ip))
        tasks.append(fetch_ip_geo(session, ip))
      except socket.gaierror:
        results["resolved_ip"] = None

    elif info["type"] == "ip":
      ip = info["value"]
      tasks.append(fetch_internetdb(session, ip))
      tasks.append(fetch_ip_geo(session, ip))
      tasks.append(loop.run_in_executor(None, search_ddg, f'"{ip}"'))

    else:  # person eller organization
      val = info["value"]
      tasks.append(loop.run_in_executor(None, search_ddg, f'"{val}"'))
      tasks.append(
          loop.run_in_executor(
              None, search_ddg, f'"{val}" site:linkedin.com OR site:github.com'
          )
      )
      tasks.append(
          loop.run_in_executor(None, search_ddg, f'"{val}" news OR breach')
      )

    gathered = await asyncio.gather(*tasks)
    results["findings"] = gathered

  return results
