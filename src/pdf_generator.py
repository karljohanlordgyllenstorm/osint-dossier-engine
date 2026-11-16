from datetime import datetime
import os
from jinja2 import Template
from weasyprint import HTML

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="sv">
<head>
<meta charset="UTF-8">
<style>
  @page {
    size: A4;
    margin: 2cm 1.8cm;
    @top-right {
      content: "OSINT DOSSIER // {{ target }}";
      font-size: 8pt;
      color: #7F8C8D;
    }
    @bottom-left {
      content: "KONFIDENTIELLT — GENERERAD {{ date }}";
      font-size: 8pt;
      color: #7F8C8D;
    }
    @bottom-right {
      content: "Sida " counter(page) " av " counter(pages);
      font-size: 8pt;
      color: #7F8C8D;
    }
  }
  @page :first {
    @top-right { content: normal; }
    @bottom-left { content: normal; }
    @bottom-right { content: normal; }
  }
  body {
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    color: #2C3E50;
    line-height: 1.5;
    font-size: 10pt;
  }
  .page-break { page-break-before: always; }
  .cover-page {
    text-align: left;
    padding-top: 120px;
  }
  .badge {
    display: inline-block;
    padding: 6px 14px;
    background-color: #2C3E50;
    color: #FFFFFF;
    font-weight: bold;
    font-size: 9pt;
    letter-spacing: 1px;
    border-radius: 3px;
  }
  .cover-title {
    font-size: 28pt;
    font-weight: bold;
    margin: 20px 0 10px 0;
    color: #1A252F;
  }
  .cover-subtitle {
    font-size: 14pt;
    color: #5D6D7E;
    margin-bottom: 40px;
  }
  .score-box {
    border-left: 6px solid #D9534F;
    background: #F8F9F9;
    padding: 20px;
    margin-top: 30px;
  }
  h1 {
    font-size: 16pt;
    color: #1A252F;
    border-bottom: 2px solid #2C3E50;
    padding-bottom: 5px;
    margin-top: 0;
  }
  h2 {
    font-size: 12pt;
    color: #2980B9;
    margin-top: 18px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    font-size: 9pt;
  }
  th, td {
    border: 1px solid #D5D8DC;
    padding: 8px 10px;
    text-align: left;
    vertical-align: top;
  }
  th {
    background-color: #2C3E50;
    color: #FFFFFF;
  }
  tr:nth-child(even) { background-color: #F8F9F9; }
  .bar-bg {
    width: 100%;
    background-color: #E5E8E8;
    height: 10px;
    border-radius: 4px;
  }
  .bar-fill {
    height: 10px;
    background-color: #2980B9;
    border-radius: 4px;
  }
  .graph-img {
    width: 100%;
    max-height: 480px;
    object-fit: contain;
    border: 1px solid #D5D8DC;
    margin-top: 10px;
  }
  .rec-card {
    background: #F4F6F7;
    border-left: 4px solid #2980B9;
    padding: 12px 15px;
    margin-bottom: 12px;
  }
  code {
    background: #EAECEE;
    padding: 2px 5px;
    border-radius: 3px;
    font-size: 8.5pt;
  }
  .osint-card {
    background: #F8F9F9;
    border: 1px solid #D5D8DC;
    padding: 10px 14px;
    margin-bottom: 10px;
    border-radius: 4px;
  }
</style>
</head>
<body>

<!-- SIDA 1: TITELSIDA -->
<div class="cover-page">
  <div class="badge">OSINT & ATTACK SURFACE DOSSIER</div>
  <div class="cover-title">{{ target }}</div>
  <div class="cover-subtitle">Automatiserad underrättelse- och exponeringsrapport</div>

  <table>
    <tr><th>Måltavla</th><td>{{ target }} (Typ: {{ target_type }})</td></tr>
    <tr><th>Upplöst IP-adress</th><td>{{ resolved_ip or 'Ej tillämpligt / Person eller Företag' }}</td></tr>
    <tr><th>Rapportdatum</th><td>{{ date }}</td></tr>
    <tr><th>Antal analyserade källor</th><td>{{ sources_count }} moduler</td></tr>
  </table>

  <div class="score-box">
    <div style="font-size: 11pt; color: #5D6D7E;">TOTAL RISKPOÄNG</div>
    <div style="font-size: 26pt; font-weight: bold; color: #C0392B;">{{ total_score }} / 100 — {{ severity }}</div>
  </div>
</div>

<!-- SIDA 2: EXECUTIVE SUMMARY & PRIORITERADE ÅTGÄRDER -->
<div class="page-break">
  <h1>1. Executive Summary</h1>
  <p>{{ ai.executive_summary }}</p>

  <h2>Top 3 Prioriterade Åtgärder</h2>
  {% for rec in ai.top_recommendations %}
  <div class="rec-card">
    <strong>[{{ rec.priority }}] {{ rec.title }}</strong><br>
    <span>{{ rec.action }}</span>
  </div>
  {% endfor %}
</div>

<!-- SIDA 3: RISKMATRIS -->
<div class="page-break">
  <h1>2. Riskmatris (7 Kategorier)</h1>
  <p>Riskpoängen beräknas deterministiskt utifrån viktade tekniska och öppna signaler.</p>
  <table>
    <thead>
      <tr>
        <th>Kategori</th>
        <th>Vikt</th>
        <th>Poäng</th>
        <th>Visualisering</th>
      </tr>
    </thead>
    <tbody>
      {% for key, cat in categories.items() %}
      <tr>
        <td><strong>{{ category_names[key] }}</strong></td>
        <td>{{ (cat.weight * 100)|int }}%</td>
        <td><strong>{{ cat.score }}/100</strong></td>
        <td>
          <div class="bar-bg"><div class="bar-fill" style="width: {{ cat.score }}%;"></div></div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<!-- SIDA 4: ENTITY-GRAF -->
<div class="page-break">
  <h1>3. Entity-graf & Infrastrukturrelationer</h1>
  <p>Grafen illustrerar kopplingar mellan måltavlan, subdomäner, IP-adresser och exponerade portar.</p>
  {% if graph_path %}
    <img src="file://{{ graph_path }}" class="graph-img" alt="Entity Graph">
  {% else %}
    <p><em>Ingen graf kunde genereras för denna måltavla.</em></p>
  {% endif %}
</div>

<!-- SIDA 5: DEDIKERAD SEKTION FÖRETAG & PERSON OSINT -->
<div class="page-break">
  <h1>4. Företags- & Personprofilering (Business & People OSINT)</h1>
  <p>Resultat från riktade sökningar efter ägare, styrelse, finansiella nyckeltal eller personers sociala profiler.</p>

  {% set found_biz_or_person = false %}
  {% for item in findings_raw %}
    {% if item.source == 'company_intelligence' or item.source == 'person_osint' %}
      {% set found_biz_or_person = true %}
      <h2>Träffar från modul: <code>{{ item.source }}</code></h2>
      {% if item.target_name %}
        <p><strong>Sökobjekt:</strong> {{ item.target_name }} {% if item.city %}(Ort: {{ item.city }}){% endif %}</p>
      {% endif %}
      {% if item.results %}
        {% for r in item.results %}
          <div class="osint-card">
            <strong>{{ r.title }}</strong><br>
            <a href="{{ r.href }}" style="color: #2980B9; font-size: 8.5pt;">{{ r.href }}</a><br>
            <span>{{ r.body }}</span>
          </div>
        {% endfor %}
      {% else %}
        <p>Inga publika träffar hittades för denna kategori.</p>
      {% endif %}
    {% endif %}
  {% endfor %}

  {% if not found_biz_or_person %}
    <p><em>Ingen specifik företags- eller personprofilering utfördes för detta mål (eller så angavs en domän/IP).</em></p>
  {% endif %}
</div>

<!-- SIDA 6+: DETALJERADE FINDINGS PER KATEGORI -->
{% for key, cat in categories.items() %}
<div class="page-break">
  <h1>5.{{ loop.index }} Detaljerad Analys: {{ category_names[key] }}</h1>
  <p><strong>Kategoripoäng:</strong> {{ cat.score }} / 100 (Vikt: {{ (cat.weight * 100)|int }}%)</p>
  <h2>Identifierade observationer</h2>
  {% if cat.findings %}
    <ul>
      {% for f in cat.findings %}
        <li>{{ f }}</li>
      {% endfor %}
    </ul>
  {% else %}
    <p>Inga avvikande risksignaler noterades i denna kategori vid skanningstillfället.</p>
  {% endif %}
</div>
{% endfor %}

<!-- ACH-MATRIS -->
<div class="page-break">
  <h1>6. ACH-matris (Analysis of Competing Hypotheses)</h1>
  <p>Strukturerad utvärdering av konkurrerande hypoteser baserat på insamlad OSINT-evidens.</p>
  <table>
    <thead>
      <tr>
        <th>Hypotes</th>
        <th>Stödjande evidens</th>
        <th>Motsägande evidens</th>
        <th>Sannolikhet</th>
      </tr>
    </thead>
    <tbody>
      {% for row in ai.ach_matrix %}
      <tr>
        <td><strong>{{ row.hypothesis }}</strong></td>
        <td>{{ row.supporting_evidence }}</td>
        <td>{{ row.contradicting_evidence }}</td>
        <td><strong>{{ row.likelihood }}</strong></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<!-- APPENDIX: FULLSTÄNDIG RÅDATA & TEKNISK INVENTERING -->
<div class="page-break">
  <h1>7. Teknisk Bilaga — Fullständig Datainventering</h1>
  <p>Detaljerad utskrift av identifierade subdomäner, DNS-poster, HTTP-säkerhetsrubriker och publika träffar.</p>

  {% for item in findings_raw %}
    <h2>Källa: {{ item.source }}</h2>
    {% if item.subdomains %}
      <p><strong>Totalt {{ item.subdomains|length }} subdomäner:</strong><br>
      <code>{{ item.subdomains|join(', ') }}</code></p>
    {% elif item.hosts %}
      <ul>
        {% for h in item.hosts %}<li><code>{{ h[0] }}</code> → {{ h[1] }}</li>{% endfor %}
      </ul>
    {% elif item.urls %}
      <ul>
        {% for u in item.urls[:25] %}<li><code>{{ u }}</code></li>{% endfor %}
      </ul>
    {% elif item.results %}
      <p><em>Sökfråga: {{ item.query }}</em></p>
      <ul>
        {% for r in item.results %}
          <li><strong>{{ r.title }}</strong> — <code>{{ r.href }}</code><br>{{ r.body }}</li>
        {% endfor %}
      </ul>
    {% elif item.data %}
      <table>
        {% for k, v in item.data.items() %}
          <tr><th style="width: 30%;">{{ k }}</th><td><code>{{ v }}</code></td></tr>
        {% endfor %}
      </table>
    {% endif %}
  {% endfor %}
</div>

</body>
</html>
"""


def generate_pdf_dossier(
    gathered_data: dict,
    risk_report: dict,
    ai_analysis: dict,
    graph_path: str,
    output_pdf: str = "osint_dossier.pdf",
) -> str:
  category_names = {
      "network_services": "Nätverk & Exponerade Tjänster",
      "email_phishing": "E-post & Phishing-surface",
      "subdomain_hygiene": "Subdomän & Infrastruktur-hygien",
      "credential_leaks": "Credential & Data Leaks",
      "code_exposure": "Kod & Utvecklar-exponering",
      "digital_footprint": "Digitalt Fotavtryck & Social Engineering",
      "reputation_news": "Rykte, Nyheter & Juridik",
  }

  template = Template(HTML_TEMPLATE)
  html_out = template.render(
      target=gathered_data.get("target", {}).get("value", "Okänd"),
      target_type=gathered_data.get("target", {}).get("type", "okänd"),
      resolved_ip=gathered_data.get("resolved_ip"),
      date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
      sources_count=len(gathered_data.get("findings", [])),
      total_score=risk_report.get("total_score", 0),
      severity=risk_report.get("severity", "OKÄND"),
      categories=risk_report.get("categories", {}),
      category_names=category_names,
      ai=ai_analysis,
      graph_path=os.path.abspath(graph_path)
      if graph_path and os.path.exists(graph_path)
      else None,
      findings_raw=gathered_data.get("findings", []),
  )

  HTML(string=html_out).write_pdf(output_pdf)
  return output_pdf
