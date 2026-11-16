# HTTP Security Headers & Tech Stack
    elif source == "http_headers_tech":
      data = item.get("data", {})
      missing = data.get("missing_security_headers", [])
      if len(missing) >= 4:
        scores["subdomain_hygiene"]["score"] += 25
        scores["subdomain_hygiene"]["findings"].append(
            f"Saknar {len(missing)} viktiga HTTP-säkerhetsheaders: {', '.join(missing)}"
        )

    # Threat Intelligence Feed (URLhaus)
    elif source == "urlhaus_threatfeed":
      data = item.get("data", {})
      if data.get("url_count", 0) > 0:
        scores["reputation_news"]["score"] += 60
        scores["reputation_news"]["findings"].append(
            f"Varning: {data.get('url_count')} historiska/aktiva träffar i URLhaus threat feed."
        )
