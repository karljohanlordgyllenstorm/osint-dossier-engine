def calculate_risk_score(gathered_data: dict) -> dict:
  """Beräknar viktad riskpoäng (0–100) över 7 säkerhetskategorier

  baserat på insamlad OSINT- och attack-surface-data.
  """
  scores = {
      "network_services": {"score": 0, "weight": 0.20, "findings": []},
      "email_phishing": {"score": 0, "weight": 0.15, "findings": []},
      "subdomain_hygiene": {"score": 0, "weight": 0.15, "findings": []},
      "credential_leaks": {"score": 0, "weight": 0.20, "findings": []},
      "code_exposure": {"score": 0, "weight": 0.10, "findings": []},
      "digital_footprint": {"score": 0, "weight": 0.10, "findings": []},
      "reputation_news": {"score": 0, "weight": 0.10, "findings": []},
  }

  findings_list = gathered_data.get("findings", [])

  for item in findings_list:
    source = item.get("source")

    # 1. Nätverk & Exponerade Tjänster (InternetDB)
    if source == "internetdb":
      data = item.get("data", {})
      ports = data.get("ports", [])
      vulns = data.get("vulns", [])

      high_risk_ports = {21, 22, 23, 445, 3389, 5900, 9200, 27017}
      exposed_sensitive = [p for p in ports if p in high_risk_ports]

      if exposed_sensitive:
        scores["network_services"]["score"] += min(
            50, len(exposed_sensitive) * 20
        )
        scores["network_services"]["findings"].append(
            f"Känsliga portar exponerade: {exposed_sensitive}"
        )
      elif ports:
        scores["network_services"]["score"] += min(20, len(ports) * 5)
        scores["network_services"]["findings"].append(f"Öppna portar: {ports}")

      if vulns:
        scores["network_services"]["score"] += min(50, len(vulns) * 15)
        scores["network_services"]["findings"].append(
            f"Potentiella sårbarheter (CVE): {vulns[:5]}"
        )

    # 2. E-post & Phishing-surface (DNS / DMARC / SPF)
    elif source == "dns":
      dns_data = item.get("data", {})
      dmarc = dns_data.get("DMARC", [])
      txt = dns_data.get("TXT", [])

      has_spf = any("v=spf1" in r.lower() for r in txt)
      if not dmarc:
        scores["email_phishing"]["score"] += 50
        scores["email_phishing"]["findings"].append(
            "Saknar DMARC-post (_dmarc) – ökad risk för domänspoofing."
        )
      elif any("p=none" in r.lower() for r in dmarc):
        scores["email_phishing"]["score"] += 25
        scores["email_phishing"]["findings"].append(
            "DMARC är satt till p=none (endast övervakning)."
        )

      if not has_spf:
        scores["email_phishing"]["score"] += 40
        scores["email_phishing"]["findings"].append(
            "Saknar SPF-post för e-postautentisering."
        )

    # 3. Subdomän & Infrastruktur-hygien (crt.sh)
    elif source == "crt.sh":
      subs = item.get("subdomains", [])
      sensitive_prefixes = ("dev.", "staging.", "test.", "admin.", "vpn.", "internal.")
      exposed_envs = [s for s in subs if s.startswith(sensitive_prefixes)]

      if exposed_envs:
        scores["subdomain_hygiene"]["score"] += min(60, len(exposed_envs) * 15)
        scores["subdomain_hygiene"]["findings"].append(
            f"Utvecklings-/admin-subdomäner synliga i CT-loggar: {exposed_envs[:5]}"
        )
      if len(subs) > 30:
        scores["subdomain_hygiene"]["score"] += 20
        scores["subdomain_hygiene"]["findings"].append(
            f"Stor subdomänyta ({len(subs)} unika certifikatposter)."
        )

    # 4, 5, 6, 7. Sökträffar (Kod, Läckor, Fotavtryck, Nyheter)
    elif source == "ddg_search":
      query = item.get("query", "").lower()
      res = item.get("results", [])
      if not res:
        continue

      if "github.com" in query or "password" in query or "leak" in query:
        scores["code_exposure"]["score"] += min(50, len(res) * 10)
        scores["code_exposure"]["findings"].append(
            f"{len(res)} publika träffar kopplade till kod/nyckelord."
        )
        scores["credential_leaks"]["score"] += min(40, len(res) * 8)
      elif "linkedin.com" in query:
        scores["digital_footprint"]["score"] += min(50, len(res) * 8)
        scores["digital_footprint"]["findings"].append(
            f"{len(res)} publika profiler/omnämnanden identifierade."
        )
      elif "news" in query or "breach" in query:
        scores["reputation_news"]["score"] += min(45, len(res) * 10)
        scores["reputation_news"]["findings"].append(
            f"{len(res)} nyhets- eller incidentomnämnanden hittades."
        )

  # Begränsa varje kategori till max 100 och räkna ut viktad totalpoäng
  total_score = 0.0
  for cat in scores.values():
    cat["score"] = min(100, cat["score"])
    total_score += cat["score"] * cat["weight"]

  total_rounded = round(total_score, 1)
  if total_rounded >= 70:
    severity = "HÖG RISK"
  elif total_rounded >= 35:
    severity = "MEDEL RISK"
  else:
    severity = "LÅG RISK"

  return {
      "total_score": total_rounded,
      "severity": severity,
      "categories": scores,
  }
