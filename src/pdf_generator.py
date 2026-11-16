<!-- APPENDIX: FULLSTÄNDIG RÅDATA & TEKNISK INVENTERING -->
<div class="page-break">
  <h1>7. Teknisk Bilaga — Fullständig Datainventering</h1>
  <p>Detaljerad utskrift av identifierade subdomäner, DNS-poster, HTTP-säkerhetsrubriker och publika dokument.</p>

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
