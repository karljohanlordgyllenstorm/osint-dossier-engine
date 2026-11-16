import asyncio
import os
import gradio as gr
from src.ai_analyst import generate_ai_analysis
from src.collectors import collect_all_data
from src.graph_builder import build_entity_graph
from src.pdf_generator import generate_pdf_dossier
from src.risk_engine import calculate_risk_score


def run_pipeline(target: str):
  if not target or not target.strip():
    return "Ange ett giltigt mål (t.ex. example.com eller 8.8.8.8).", None, None

  target_clean = target.strip()
  safe_name = "".join(c if c.isalnum() else "_" for c in target_clean)
  graph_file = f"graph_{safe_name}.png"
  pdf_file = f"dossier_{safe_name}.pdf"

  # 1 & 2. Samla data parallellt
  loop = asyncio.new_event_loop()
  asyncio.set_event_loop(loop)
  gathered = loop.run_until_complete(collect_all_data(target_clean))

  # 3. Bygg entity-graf
  build_entity_graph(gathered, output_path=graph_file)

  # 4. Beräkna riskpoäng
  risk = calculate_risk_score(gathered)

  # 5. Kör AI-analys (Ollama / fallback)
  ai_res = generate_ai_analysis(gathered, risk)

  # 6. Generera 13-sidig PDF-dossier
  generate_pdf_dossier(gathered, risk, ai_res, graph_file, output_pdf=pdf_file)

  summary_md = f"""### Analys klar för `{target_clean}`
- **Identifierad typ:** `{gathered['target']['type']}`
- **Upplöst IP:** `{gathered.get('resolved_ip') or 'N/A'}`
- **Total Riskpoäng:** **{risk['total_score']} / 100 ({risk['severity']})**

#### Executive Summary
{ai_res.get('executive_summary', '')}
"""
  return summary_md, graph_file, pdf_file


with gr.Blocks(title="OSINT Dossier Engine", theme=gr.themes.Soft()) as demo:
  gr.Markdown("# OSINT & Attack Surface Dossier Engine")
  gr.Markdown(
      "Mata in en domän, IP-adress, ett företagsnamn eller en person för att"
      " generera en komplett PDF-dossier."
  )

  with gr.Row():
    target_input = gr.Textbox(
        label="Target (t.ex. example.com, 1.1.1.1, Acme Corp)",
        placeholder="example.com",
    )
    run_btn = gr.Button("Starta OSINT-skanning", variant="primary")

  status_output = gr.Markdown()

  with gr.Row():
    graph_output = gr.Image(label="Entity-graf")
    pdf_output = gr.File(label="Ladda ner PDF-dossier")

  run_btn.click(
      fn=run_pipeline,
      inputs=[target_input],
      outputs=[status_output, graph_output, pdf_output],
  )

if __name__ == "__main__":
  demo.launch(share=True)
