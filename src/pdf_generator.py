import base64
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from weasyprint import HTML


def _img_to_base64(path: str) -> str:
  if not path or not os.path.exists(path):
    return ""
  with open(path, "rb") as f:
    return base64.b64encode(f.read()).decode("utf-8")


def generate_pdf_dossier(
    gathered: dict,
    risk: dict,
    ai_res: dict,
    graph_path: str,
    output_pdf: str = "osint_dossier.pdf",
) -> str:
  target_val = html.escape(gathered["target"]["value"])
  target_type = html.escape(gathered["target"]["type"].upper())
  resolved_ip = html.escape(str(gathered.get("resolved_ip") or "Ej applicerbart"))
  ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
  graph_b64 = _img_to_base64(graph_path)

  # Generera Master-hash för hela rapporten (Chain of Custody)
  master_json = json.dumps(gathered, sort_keys=True, default=str)
  master_hash = hashlib.sha256(master_json.encode("utf-8")).hexdigest()

  score = risk["total_score"]
  badge_color = (
      "#dc2626" if score >= 65 else ("#d97706" if score >= 35 else "#059669")
  )

  findings_rows = ""
  for item in risk.get("findings_breakdown", []):
    sev_color = (
        "#dc2626"
        if item["severity"] in ["KRITISK", "HÖG"]
        else ("#d97706" if item["severity"] == "MEDEL" else "#0284c7")
    )
    findings_rows += f"""
        <tr>
            <td><span class="sev-pill" style="background:{sev_color};">{html.escape(item['severity'])}</span></td>
            <td><strong>{html.escape(item['category'])}</strong></td>
            <td>{html.escape(item['title'])}<br><small style="color:#475569;">{html.escape(item['detail'])}</small></td>
            <td style="text-align:center;">+{item['points']}</td>
        </tr>
        """
  if not findings_rows:
    findings_rows = (
        "<tr><td colspan='4'>Inga förhöjda riskindikatorer"
        " identifierades.</td></tr>"
    )

  rec_items = "".join(
      f"<li>{html.escape(r)}</li>" for r in ai_res.get("recommendations", [])
  )

  news_html = ""
  company_person_html = ""
  diaries_property_html = ""
  contacts_socials_html = ""
  youtube_html = ""
  raw_sections = ""

  for f in gathered.get("findings", []):
    src = f.get("source", "okänd")

    if src == "google_news":
      articles = f.get("articles", [])
      if articles:
        items = "".join(
            f"<li><strong>{html.escape(a.get('title',''))}</strong> "
            f"<span style='color:#64748b;'>({html.escape(a.get('source',''))} — {html.escape(a.get('published',''))})</span><br>"
            f"<span class='url-wrap'>{html.escape(a.get('url',''))}</span></li>"
            for a in articles
        )
        news_html += f"<ul>{items}</ul>"

    elif src in ["company_intelligence", "person_osint", "official_registry"]:
      res = f.get("results", [])
      reg_data = f.get("registry_data")

      if res:
        label = (
            "Bolagsdata, Bokslut & Nyckeltal"
            if src == "company_intelligence"
            else (
                "Officiella Registeruppgifter"
                if src == "official_registry"
                else "Personkopplingar & Styrelseroller"
            )
        )
        items = "".join(
            f"<li><strong>{html.escape(r.get('title',''))}</strong><br>"
            f"<span class='url-wrap'>{html.escape(r.get('href',''))}</span><br>"
            f"<span style='color:#334155;'>{html.escape(r.get('body',''))}</span></li>"
            for r in res
        )
        company_person_html += f"<h3>{label}</h3><ul class='data-list'>{items}</ul>"
      elif reg_data:
        company_person_html += (
            f"<h3>Officiellt Register (API)</h3>"
            f"<div class='mono'><pre>{html.escape(json.dumps(reg_data, indent=2, ensure_ascii=False))}</pre></div>"
        )

    elif src == "public_diaries_properties":
      res = f.get("results", [])
      if res:
        items = "".join(
            f"<li><strong>{html.escape(r.get('title',''))}</strong><br>"
            f"<span class='url-wrap'>{html.escape(r.get('href',''))}</span><br>"
            f"<span style='color:#334155;'>{html.escape(r.get('body',''))}</span></li>"
            for r in res
        )
        diaries_property_html += (
            f"<h3>Allmänna Diarier, Beslut & Fastighetsregister</h3>"
            f"<ul class='data-list'>{items}</ul>"
        )

    elif src == "public_contacts_socials":
      data = f.get("data", {})
      emails = data.get("emails", [])
      socials = data.get("social_profiles", [])
      if emails or socials:
        e_str = (
            ", ".join(html.escape(e) for e in emails)
            or "Inga publika e-postadresser hittades"
        )
        s_items = "".join(
            f"<li><span class='url-wrap'>{html.escape(s)}</span></li>"
            for s in socials
        ) or "<li>Inga officiella sociala länkar hittades</li>"
        contacts_socials_html += f"""
        <div class="box">
            <p><strong>Publika e-postadresser:</strong> {e_str}</p>
            <p><strong>Identifierade sociala kanaler:</strong></p>
            <ul class='data-list'>{s_items}</ul>
        </div>
        """

    elif src == "youtube_osint":
      vids = f.get("results", [])
      if vids:
        items = "".join(
            f"<li><strong>{html.escape(v.get('title',''))}</strong><br>"
            f"<span class='url-wrap'>{html.escape(v.get('href',''))}</span><br>"
            f"<span style='color:#334155;'>{html.escape(v.get('body',''))}</span></li>"
            for v in vids
        )
        youtube_html += f"<h3>YouTube-medieframträdanden</h3><ul class='data-list'>{items}</ul>"

    elif src == "crt.sh":
      subs = f.get("subdomains", [])
      raw_sections += (
          f"<h3>Subdomäner (Certificate Transparency: {len(subs)} st)</h3>"
      )
      raw_sections += f"<p class='mono'>{', '.join(html.escape(s) for s in subs[:100]) or 'Inga hittades'}</p>"

    elif src == "dns":
      raw_sections += "<h3>DNS-poster</h3><ul>"
      for k, v in f.get("data", {}).items():
        raw_sections += f"<li><strong>{k}:</strong> {html.escape(', '.join(v) if v else 'Saknas')}</li>"
      raw_sections += "</ul>"

    elif src == "http_headers_tech":
      d = f.get("data", {})
      raw_sections += "<h3>HTTP-säkerhet & Teknikstack</h3>"
      raw_sections += f"<p><strong>Identifierad teknik:</strong> {html.escape(', '.join(d.get('detected_technologies', [])) or 'Okänd')}</p>"
      raw_sections += f"<p><strong>Saknade säkerhetsrubriker:</strong> {html.escape(', '.join(d.get('missing_security_headers', [])) or 'Inga')}</p>"

    elif src == "ddg_search":
      res = f.get("results", [])
      if res:
        raw_sections += f"<h3>Sökmotorinventering ({html.escape(f.get('query', ''))})</h3><ul>"
        for r in res[:10]:
          raw_sections += f"<li><strong>{html.escape(r.get('title',''))}</strong><br><span class='url-wrap'>{html.escape(r.get('href',''))}</span><br><span style='color:#475569;'>{html.escape(r.get('body',''))}</span></li>"
        raw_sections += "</ul>"

  if not news_html:
    news_html = "<p style='color:#64748b;'>Inga aktuella nyheter hittades.</p>"
  if not company_person_html:
    company_person_html = (
        "<p style='color:#64748b;'>Inga bolagsdata eller registerkopplingar hittades.</p>"
    )
  if not diaries_property_html:
    diaries_property_html = (
        "<p style='color:#64748b;'>Inga publika diarier eller fastighetskopplingar hittades.</p>"
    )
  if not contacts_socials_html and not youtube_html:
    contacts_socials_html = (
        "<p style='color:#64748b;'>Inga publika kontakter hittades.</p>"
    )

  html_content = f"""
    <!DOCTYPE html>
    <html lang="sv">
    <head>
    <meta charset="UTF-8">
    <style>
        @page {{
            size: A4;
            margin: 18mm 16mm 18mm 16mm;
            @bottom-right {{
                content: "Sida " counter(page) " av " counter(pages);
                font-family: 'Helvetica Neue', Arial, sans-serif;
                font-size: 8pt;
                color: #64748b;
            }}
            @bottom-left {{
                content: "LEGAL EVIDENCE DOSSIER // {target_val}";
                font-family: 'Helvetica Neue', Arial, sans-serif;
                font-size: 8pt;
                color: #64748b;
            }}
        }}
        body {{
            font-family: 'Helvetica Neue', Arial, sans-serif;
            color: #1e293b;
            line-height: 1.48;
            font-size: 9.5pt;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}
        .url-wrap {{
            font-family: 'Courier New', monospace;
            font-size: 8pt;
            color: #0284c7;
            word-break: break-all;
            overflow-wrap: break-word;
        }}
        .cover {{
            background: #0f172a;
            color: #ffffff;
            padding: 32px 28px;
            border-radius: 6px;
            margin-bottom: 20px;
        }}
        .cover h1 {{
            margin: 0 0 6px 0;
            font-size: 20pt;
        }}
        .cover .subtitle {{
            color: #94a3b8;
            font-size: 10pt;
            margin-bottom: 18px;
        }}
        .meta-grid {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
        }}
        .meta-grid td {{
            padding: 6px 8px;
            background: #1e293b;
            border: 1px solid #334155;
            font-size: 8.5pt;
        }}
        h2 {{
            color: #0f172a;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 4px;
            margin-top: 20px;
            font-size: 12.5pt;
            page-break-after: avoid;
        }}
        h3 {{
            color: #334155;
            font-size: 10pt;
            margin-top: 12px;
            margin-bottom: 4px;
            page-break-after: avoid;
        }}
        .box {{
            background: #f8fafc;
            border-left: 4px solid #2563eb;
            padding: 10px 14px;
            margin: 10px 0;
            border-radius: 0 4px 4px 0;
        }}
        .risk-badge {{
            display: inline-block;
            background: {badge_color};
            color: #fff;
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 9.5pt;
        }}
        table.data-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
            font-size: 8.5pt;
        }}
        table.data-table th {{
            background: #0f172a;
            color: #fff;
            text-align: left;
            padding: 6px 8px;
        }}
        table.data-table td {{
            border-bottom: 1px solid #cbd5e1;
            padding: 6px 8px;
            vertical-align: top;
            word-break: break-word;
        }}
        .sev-pill {{
            color: #fff;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 7.5pt;
            font-weight: bold;
            display: inline-block;
        }}
        .mono {{
            font-family: 'Courier New', monospace;
            font-size: 7.5pt;
            background: #f1f5f9;
            padding: 8px;
            border-radius: 4px;
            word-break: break-all;
            overflow-wrap: break-word;
        }}
        .data-list li {{
            margin-bottom: 8px;
        }}
        .graph-box {{
            text-align: center;
            margin: 12px 0;
            page-break-inside: avoid;
        }}
        .graph-box img {{
            max-width: 100%;
            max-height: 320px;
            border: 1px solid #cbd5e1;
            border-radius: 4px;
        }}
        .page-break {{
            page-break-before: always;
        }}
    </style>
    </head>
    <body>

    <div class="cover">
        <div style="font-size:8pt; letter-spacing:1.5px; color:#38bdf8; font-weight:bold; margin-bottom:4px;">
            LEGAL-GRADE OSINT &amp; EVIDENCE DOSSIER
        </div>
        <h1>Dossier: {target_val}</h1>
        <div class="subtitle">Verifierbar intelligens för juridisk prövning och due diligence</div>
        <table class="meta-grid">
            <tr>
                <td><strong>Måltyp:</strong> {target_type}</td>
                <td><strong>Upplöst IP:</strong> {resolved_ip}</td>
                <td><strong>Tidsstämpel (UTC):</strong> {ts}</td>
                <td><strong>Risknivå:</strong> <span class="risk-badge">{risk['severity']} ({score}/100)</span></td>
            </tr>
        </table>
        <div style="margin-top: 10px; font-size: 7.5pt; color: #94a3b8; font-family: monospace; word-break: break-all;">
            <strong>Chain of Custody SHA-256 Hash:</strong> {master_hash}
        </div>
    </div>

    <h2>1. Executive Summary &amp; Juridisk Sammanfattning</h2>
    <div class="box">{html.escape(ai_res.get('executive_summary', ''))}</div>

    <h2>2. Bolagsdata, Bokslut &amp; Officiella Register</h2>
    {company_person_html}

    <h2>3. Officiella Diarier, Beslut &amp; Fastighetsregister</h2>
    {diaries_property_html}

    <h2>4. Verifierad Mediebevakning</h2>
    {news_html}

    <h2>5. Sociala Kanaler &amp; Publika Kontakter</h2>
    {contacts_socials_html}
    {youtube_html}

    <h2>6. Exponerings- &amp; Riskanalys</h2>
    <p>{html.escape(ai_res.get('technical_analysis', ''))}</p>
    <table class="data-table">
        <thead>
            <tr>
                <th style="width:14%;">Allvarlighet</th>
                <th style="width:20%;">Kategori</th>
                <th style="width:56%;">Fynd &amp; Detaljer</th>
                <th style="width:10%; text-align:center;">Poäng</th>
            </tr>
        </thead>
        <tbody>{findings_rows}</tbody>
    </table>

    <h2>7. Visuell Relationskarta (Entity Graph)</h2>
    <div class="graph-box">
        <img src="data:image/png;base64,{graph_b64}" alt="Entity Graph" />
    </div>

    <h2>8. Rekommendationer för Fortsatt Utredning</h2>
    <ul>{rec_items}</ul>

    <div class="page-break"></div>
    <h2>9. Teknisk Bilaga &amp; Evidenskedja (Raw Data Audit Trail)</h2>
    <p style="color:#475569;">Denna bilaga innehåller rådata, subdomäner, säkerhetsrubriker samt kryptografisk verifiering för juridisk hälsa.</p>
    <div class="mono" style="margin-bottom: 12px;">
        <strong>Master SHA-256 Hash:</strong> {master_hash}
    </div>
    {raw_sections}

    </body>
    </html>
    """
  HTML(string=html_content).write_pdf(output_pdf)
  return output_pdf
