import argparse
import asyncio
from src.ai_analyst import generate_ai_analysis
from src.collectors import collect_all_data
from src.graph_builder import build_entity_graph
from src.pdf_generator import generate_pdf_dossier
from src.risk_engine import calculate_risk_score


async def main_cli():
  parser = argparse.ArgumentParser(
      description="OSINT & Attack Surface Dossier CLI"
  )
  parser.add_argument(
      "--target", required=True, help="Mål att skanna (domän, IP eller företag)"
  )
  parser.add_argument(
      "--city", default="", help="Stad/ort (valfritt för person-OSINT)"
  )
  parser.add_argument(
      "--output", default="osint_report.pdf", help="Namn på PDF-rapporten"
  )

  args = parser.parse_args()

  print(f"[+] Startar skanning för mål: {args.target}...")

  gathered = await collect_all_data(args.target, city=args.city)
  risk = calculate_risk_score(gathered)
  ai_res = generate_ai_analysis(gathered, risk)

  graph_file = f"graph_{args.target}.png"
  build_entity_graph(gathered, output_path=graph_file)

  pdf_path = generate_pdf_dossier(
      gathered, risk, ai_res, graph_file, output_pdf=args.output
  )
  print(f"[+] Skanning klar! PDF-rapport sparad till: {pdf_path}")


if __name__ == "__main__":
  asyncio.run(main_cli())
