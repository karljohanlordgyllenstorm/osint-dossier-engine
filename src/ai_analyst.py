import json
import requests


def generate_ai_analysis(
    gathered_data: dict, risk_report: dict, model: str = "qwen2.5:7b"
) -> dict:
  """Anropar lokal Ollama-instans i Colab för att skapa Executive Summary,

  ACH-matris och prioriterade åtgärder. Har inbyggd fallback om Ollama saknas.
  """
  target = gathered_data.get("target", {}).get("value", "Okänt mål")
  total_score = risk_report.get("total_score", 0)
  severity = risk_report.get("severity", "OKÄND")

  # Komprimera datan så prompten håller sig effektiv och fokuserad
  summary_payload = {
      "target": gathered_data.get("target"),
      "resolved_ip": gathered_data.get("resolved_ip"),
      "total_risk_score": total_score,
      "severity": severity,
      "categories": risk_report.get("categories"),
      "sources_count": len(gathered_data.get("findings", [])),
  }

  prompt = f"""Du är en senior cybersäkerhets- och OSINT-analytiker. Analysera följande insamlade data om måltavlan '{target}' och svara ENBART med giltig JSON utan markdown-kodblock.

DATA:
{json.dumps(summary_payload, ensure_ascii=False)}

Returnera exakt följande JSON-struktur på svenska:
{{
  "executive_summary": "En affärsmässig och teknisk sammanfattning på 2-3 stycken om exponering, riskbild och övergripande säkerhetshygien.",
  "ach_matrix": [
    {{
      "hypothesis": "H1: Måltavlan har brister i konfiguration/exponering utan tecken på aktivt intrång",
      "supporting_evidence": "Konkret evidens från datan som stödjer hypotesen",
      "contradicting_evidence": "Evidens som talar emot",
      "likelihood": "Hög / Medel / Låg"
    }},
    {{
      "hypothesis": "H2: Måltavlan utgör en attraktiv attackyta för phishing eller opportunistisk skanning",
      "supporting_evidence": "Konkret evidens (t.ex. saknad DMARC, öppna portar)",
      "contradicting_evidence": "Evidens som talar emot",
      "likelihood": "Hög / Medel / Låg"
    }},
    {{
      "hypothesis": "H3: Måltavlan upprätthåller god grundläggande säkerhetshygien",
      "supporting_evidence": "Konkret evidens",
      "contradicting_evidence": "Evidens som talar emot",
      "likelihood": "Hög / Medel / Låg"
    }}
  ],
  "top_recommendations": [
    {{
      "priority": "1 (Kritisk)",
      "title": "Kort rubrik på åtgärd",
      "action": "Detaljerad teknisk beskrivning av vad som bör åtgärdas och varför."
    }},
    {{
      "priority": "2 (Hög)",
      "title": "Kort rubrik på åtgärd",
      "action": "Detaljerad teknisk beskrivning."
    }},
    {{
      "priority": "3 (Medel)",
      "title": "Kort rubrik på åtgärd",
      "action": "Detaljerad teknisk beskrivning."
    }}
  ]
}}"""

  try:
    resp = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        },
        timeout=90,
    )
    if resp.status_code == 200:
      raw_text = resp.json().get("response", "{}")
      return json.loads(raw_text)
  except Exception:
    pass

  # Fallback om Ollama inte körs i bakgrunden
  return {
      "executive_summary": (
          f"Automatiserad OSINT-kartläggning av {target} resulterade i en"
          f" total riskpoäng på {total_score}/100 ({severity}). Analysen bygger"
          " på passiv insamling från öppna källor inklusive DNS, CT-loggar,"
          " portdatabaser och publika sökträffar."
      ),
      "ach_matrix": [
          {
              "hypothesis": (
                  "H1: Exponerad attackyta beror på normal drift utan"
                  " härdning"
              ),
              "supporting_evidence": (
                  "Publika DNS- och certifikatposter identifierade."
              ),
              "contradicting_evidence": (
                  "Inga direkta tecken på pågående intrång i öppna källor."
              ),
              "likelihood": "Medel",
          },
          {
              "hypothesis": (
                  "H2: Ökad risk för e-postspoofing och social engineering"
              ),
              "supporting_evidence": (
                  "Eventuella brister i DMARC/SPF eller synliga subdomäner."
              ),
              "contradicting_evidence": "Kräver manuell verifiering av e-postflöden.",
              "likelihood": "Medel",
          },
      ],
      "top_recommendations": [
          {
              "priority": "1 (Kritisk)",
              "title": "Granska exponerade portar och tjänster",
              "action": (
                  "Säkerställ att administrativa portar (SSH, RDP, databaser)"
                  " inte är öppna direkt mot internet utan VPN eller IP-restriktioner."
              ),
          },
          {
              "priority": "2 (Hög)",
              "title": "Stärk e-postsäkerheten (DMARC/SPF)",
              "action": (
                  "Implementera eller skärp DMARC-policyn till p=quarantine"
                  " eller p=reject för att motverka domänspoofing."
              ),
          },
          {
              "priority": "3 (Medel)",
              "title": "Inventera subdomäner och certifikat",
              "action": (
                  "Avveckla inaktiva dev/staging-miljöer som syns i"
                  " Certificate Transparency-loggar."
              ),
          },
      ],
  }
