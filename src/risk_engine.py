def calculate_risk_score(gathered_data: dict) -> dict:
  findings_list = gathered_data.get("findings", [])

  # 7 Kategorier med vikter
  categories = {
      "network_services": {"weight": 0.20, "score": 0, "findings": []},
      "email_phishing": {"weight": 0.15, "score": 0, "findings": []},
      "subdomain_hygiene": {"weight": 0.15, "score": 0, "findings": []},
      "credential_leaks": {"weight": 0.15, "score": 0, "findings": []},
      "code_exposure": {"weight": 0.10, "score": 0, "findings": []},
      "digital_footprint": {"weight": 0.15, "score": 0, "findings": []},
      "reputation_news": {"weight": 0.10, "score": 0, "findings": []},
  }

  for item in findings_list:
    source = item.get("source")

    # InternetDB (Shodan) - Exponerade portar & sårbarheter
    if source == "internetdb":
      data = item.get("data", {})
      ports = data.get("ports", [])
      vulns = data.get("vulns", [])

      if ports:
        categories["network_services"]["score"] += min(len(ports) * 5, 50)
        categories["network_services"]["findings"].append(
            f"Exponerade portar hittade via InternetDB: {ports}"
        )

      if vulns:
        categories["network_services"]["score"] += min(len(vulns) * 15, 50)
        categories["network_services"]["findings"].append(
            f"Kända sårbarheter (CVE) upptäckta: {vulns}"
        )

    # DNS & E-post (SPF / DMARC)
    elif source == "dns":
      data = item.get("data", {})
      txt_records = data.get("TXT", [])
      dmarc = data.get("DMARC", [])

      has_spf = any("v=spf1" in r.lower() for r in txt_records)
      if not has_spf:
        categories["email_phishing"]["score"] += 40
        categories["email_phishing"]["findings"].append(
            "Saknar SPF-post i DNS, vilket ökar risken för e-postförfalskning"
            " (spoofing)."
        )

      if not dmarc:
        categories["email_phishing"]["score"] += 40
        categories["email_phishing"]["findings"].append(
            "Saknar DMARC-policy i DNS."
        )

    # SSL / TLS Certifikat
    elif source == "ssl":
      if item.get("error"):
        categories["subdomain_hygiene"]["score"] += 30
        categories["subdomain_hygiene"]["findings"].append(
            f"SSL-certifikat kunde inte verifieras: {item.get('error')}"
        )

    # HTTP Security Headers & Tech Stack
    elif source == "http_headers_tech":
      data = item.get("data", {})
      missing = data.get("missing_security_headers", [])
      if len(missing) >= 3:
        categories["subdomain_hygiene"]["score"] += 25
        categories["subdomain_hygiene"]["findings"].append(
            f"Saknar {len(missing)} viktiga HTTP-säkerhetsheaders:"
            f" {', '.join(missing)}"
        )

    # Threat Intelligence Feed (URLhaus)
    elif source == "urlhaus_threatfeed":
      data = item.get("data", {})
      if data.get("url_count", 0) > 0:
        categories["reputation_news"]["score"] += 60
        categories["reputation_news"]["findings"].append(
            f"Varning: {data.get('url_count')} historiska/aktiva träffar i"
            " URLhaus threat feed."
        )

    # Subdomäner (crt.sh / Hackertarget)
    elif source == "crt.sh":
      subs = item.get("subdomains", [])
      if len(subs) > 20:
        categories["subdomain_hygiene"]["score"] += min(len(subs), 40)
        categories["subdomain_hygiene"]["findings"].append(
            f"Stort antal subdomäner upptäckta ({len(subs)} st), ökar"
            " attackytan."
        )

  # Begränsa poäng per kategori till max 100
  total_weighted_score = 0
  for cat_key, cat_data in categories.items():
    cat_data["score"] = min(max(cat_data["score"], 0), 100)
    total_weighted_score += cat_data["score"] * cat_data["weight"]

  total_score = int(round(total_weighted_score))

  # Sätt allvarlighetsgrad (Severity)
  if total_score >= 70:
    severity = "KRITISK"
  elif total_score >= 45:
    severity = "HÖG"
  elif total_score >= 20:
    severity = "MEDEL"
  else:
    severity = "LÅG"

  return {
      "total_score": total_score,
      "severity": severity,
      "categories": categories,
  }
