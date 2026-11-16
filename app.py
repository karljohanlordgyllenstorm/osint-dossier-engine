import asyncio
import os
import gradio as gr
from src.ai_analyst import generate_ai_analysis
from src.collectors import collect_all_data
from src.database import get_scan_history, save_scan
from src.graph_builder import build_entity_graph
from src.pdf_generator import generate_pdf_dossier
from src.risk_engine import calculate_risk_score


def run_pipeline(target: str, city: str):
  if not target or not target.strip():
    return (
        "Ange ett giltigt mål (t.ex. example.com, Acme Corp eller Anna"
        " Andersson).",
        None,
        None,
        "Ingen historik tillgänglig.",
    )

  target_clean = target.strip()
  city_clean = city.strip() if city else ""

  # Skapa säkra filnamn
  safe_name = "".join(
      c if c.isalnum() else "_" for c in f"{target_clean}_{city_clean}"
  )
  graph_file = f"graph_{safe_name}.png"
  pdf_file = f"dossier_{safe_name}.pdf"

  # 1 & 2. Samla data parallellt
  loop = asyncio.new_event_loop()
  asyncio.set_event_loop(loop)
  gathered = loop.run_until_complete(
      collect_all_data(target_clean, city=city_clean)
  )

  # 3. Bygg entity-graf
  build_entity_graph(gathered, output_path=graph_file)

  # 4. Beräkna riskpoäng
  risk = calculate_risk_score(gathered)

  # 5. Spara skanningen i SQLite-databasen
  save_scan(gathered, risk)

  # 6. Kör AI-analys
  ai_res = generate_ai_analysis(gathered, risk)

  # 7. Generera PDF-dossier
  generate_pdf_dossier(gathered, risk, ai_res, graph_file, output_pdf=pdf_file)

  # Hämta tidigare historik för målet
  history_rows = get_scan_history(target_clean)
  history_md = "### Tidigare skanningar för detta mål:\n"
  if history_rows:
    for h in history_rows:
      history_md += (
          f"- **{h[0]}**: Riskpoäng **{h[1]}/100** ({h[2]})\n"
      )
  else:
    history_md += "Inga tidigare sparade skanningar hittades."

  summary_md = f"""### Analys klar för `{target_clean}` {f"({city_clean})" if city_clean else ""}
- **Identifierad typ:** `{gathered['target']['type']}`
- **Upplöst IP / Sökdata:** `{gathered.get('resolved_ip') or 'Företag / Person (OSINT)'}`
- **Total Riskpoäng:** **{risk['total_score']} / 100 ({risk['severity']})**

#### Executive Summary
{ai_res.get('executive_summary', '')}
"""
  return summary_md, graph_file, pdf_file, history_md


with gr.Blocks(title="OSINT Dossier Engine", theme=gr.themes.Soft()) as demo:
  gr.Markdown("# OSINT & Attack Surface Dossier Engine")
  gr.Markdown(
      "Mata in en domän, IP-adress, ett företagsnamn eller en person för att"
      " generera en komplett PDF-dossier samt spara historik."
  )

  with gr.Row():
    target_input = gr.Textbox(
        label="Target (Domän, Företagsnamn eller Person)",
        placeholder="t.ex. acme.com eller Anna Andersson",
    )
    city_input = gr.Textbox(
        label="Stad / Ort (Valfritt, primärt för personer)",
        placeholder="t.ex. Stockholm",
    )

  run_btn = gr.Button("Starta OSINT-skanning & Generera Dossier", variant="primary")
  
  with gr.Row():
    status_output = gr.Markdown()
    history_output = gr.Markdown(label="Skanningshistorik")

  with gr.Row():
    graph_output = gr.Image(label="Entity-graf")
    pdf_output = gr.File(label="Ladda ner PDF-dossier")

  run_btn.click(
      fn=run_pipeline,
      inputs=[target_input, city_input],
      outputs=[status_output, graph_output, pdf_output, history_output],
  )

if __name__ == "__main__":
  demo.launch(share=True)
