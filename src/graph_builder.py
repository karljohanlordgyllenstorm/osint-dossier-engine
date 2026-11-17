import matplotlib.pyplot as plt
import networkx as nx


def build_entity_graph(
    gathered_data: dict, output_path: str = "entity_graph.png"
) -> str:
  G = nx.Graph()
  target_val = gathered_data["target"]["value"]
  G.add_node(target_val, category="target")

  resolved_ip = gathered_data.get("resolved_ip")
  if resolved_ip:
    G.add_node(resolved_ip, category="ip")
    G.add_edge(target_val, resolved_ip)

  for f in gathered_data.get("findings", []):
    src = f.get("source")

    if src == "crt.sh":
      for sub in f.get("subdomains", [])[:12]:
        G.add_node(sub, category="subdomain")
        G.add_edge(target_val, sub)

    elif src == "dns":
      for mx in f.get("data", {}).get("MX", [])[:4]:
        clean_mx = mx.split()[-1].rstrip(".")
        G.add_node(f"MX: {clean_mx}", category="dns")
        G.add_edge(target_val, f"MX: {clean_mx}")
      for ns in f.get("data", {}).get("NS", [])[:4]:
        clean_ns = ns.rstrip(".")
        G.add_node(f"NS: {clean_ns}", category="dns")
        G.add_edge(target_val, f"NS: {clean_ns}")

    elif src == "internetdb" and resolved_ip:
      for port in f.get("data", {}).get("ports", [])[:10]:
        p_label = f"Port {port}"
        G.add_node(p_label, category="port")
        G.add_edge(resolved_ip, p_label)

    elif src == "public_contacts_socials":
      data = f.get("data", {})
      for email in data.get("emails", [])[:5]:
        G.add_node(email, category="contact")
        G.add_edge(target_val, email)
      for soc in data.get("social_profiles", [])[:6]:
        short_soc = soc.replace("https://", "").replace("http://", "").split("?")[0][:32]
        G.add_node(short_soc, category="social")
        G.add_edge(target_val, short_soc)

    elif src == "google_news":
      for art in f.get("articles", [])[:4]:
        news_src = art.get("source") or "Nyhetsartikel"
        label = f"News: {news_src[:25]}"
        G.add_node(label, category="news")
        G.add_edge(target_val, label)

    elif src == "youtube_osint":
      for vid in f.get("results", [])[:3]:
        title = vid.get("title", "YouTube")[:28]
        G.add_node(f"YT: {title}", category="media")
        G.add_edge(target_val, f"YT: {title}")

    elif src in ["company_intelligence", "person_osint"]:
      for item in f.get("results", [])[:8]:
        title = item.get("title", "")[:30]
        if title:
          G.add_node(title, category="osint")
          G.add_edge(target_val, title)

  color_map = {
      "target": "#0f172a",
      "ip": "#2563eb",
      "subdomain": "#0284c7",
      "dns": "#059669",
      "port": "#dc2626",
      "contact": "#d97706",
      "social": "#7c3aed",
      "news": "#0891b2",
      "media": "#e11d48",
      "osint": "#4f46e5",
  }
  colors = [
      color_map.get(G.nodes[n].get("category", "osint"), "#475569")
      for n in G.nodes
  ]

  plt.figure(figsize=(12, 7.5), dpi=160)
  pos = nx.spring_layout(G, k=0.95, iterations=50, seed=42)
  nx.draw_networkx_nodes(
      G, pos, node_color=colors, node_size=750, alpha=0.92
  )
  nx.draw_networkx_edges(G, pos, edge_color="#94a3b8", width=1.1, alpha=0.65)
  nx.draw_networkx_labels(
      G,
      pos,
      font_size=7,
      font_weight="bold",
      bbox=dict(
          boxstyle="round,pad=0.2", fc="white", ec="#cbd5e1", alpha=0.88
      ),
  )
  plt.title(
      f"OSINT & Relationskarta — {target_val}",
      fontsize=13,
      fontweight="bold",
      pad=12,
  )
  plt.axis("off")
  plt.tight_layout()
  plt.savefig(output_path, bbox_inches="tight")
  plt.close()
  return output_path
