import matplotlib.pyplot as plt
import networkx as nx


def build_entity_graph(
    gathered_data: dict, output_path: str = "entity_graph.png"
) -> str:
  """Bygger och sparar en visuell entity-graf över måltavlans relationer."""
  G = nx.Graph()
  target_val = gathered_data.get("target", {}).get("value", "Target")
  G.add_node(target_val, color="#D9534F", size=1400, label=target_val)

  resolved_ip = gathered_data.get("resolved_ip")
  if resolved_ip:
    G.add_node(resolved_ip, color="#F0AD4E", size=900, label=resolved_ip)
    G.add_edge(target_val, resolved_ip)

  for item in gathered_data.get("findings", []):
    source = item.get("source")

    # Lägg till subdomäner (max 15 för att grafen ska förbli läsbar i PDF)
    if source == "crt.sh":
      for sub in item.get("subdomains", [])[:15]:
        if sub != target_val:
          G.add_node(sub, color="#5BC0DE", size=500, label=sub)
          G.add_edge(target_val, sub)

    # Lägg till öppna portar och CVE:er kopplade till IP
    elif source == "internetdb":
      data = item.get("data", {})
      ip_node = data.get("ip") or resolved_ip or target_val
      for port in data.get("ports", [])[:10]:
        p_label = f"Port {port}"
        G.add_node(p_label, color="#5CB85C", size=350, label=p_label)
        G.add_edge(ip_node, p_label)
      for cve in data.get("vulns", [])[:5]:
        G.add_node(cve, color="#8E44AD", size=400, label=cve)
        G.add_edge(ip_node, cve)

    # Lägg till MX-servrar från DNS
    elif source == "dns":
      for mx in item.get("data", {}).get("MX", [])[:3]:
        mx_clean = mx.split()[-1].rstrip(".")
        G.add_node(mx_clean, color="#3498DB", size=450, label=f"MX: {mx_clean}")
        G.add_edge(target_val, mx_clean)

  plt.figure(figsize=(11, 7.5))
  pos = nx.spring_layout(G, k=0.65, seed=42)

  colors = [nx.get_node_attributes(G, "color").get(n, "#95A5A6") for n in G.nodes()]
  sizes = [nx.get_node_attributes(G, "size").get(n, 400) for n in G.nodes()]
  labels = nx.get_node_attributes(G, "label")

  nx.draw(
      G,
      pos,
      labels=labels,
      with_labels=True,
      node_color=colors,
      node_size=sizes,
      font_size=8,
      font_weight="bold",
      edge_color="#BDC3C7",
      alpha=0.9,
  )

  plt.title(f"OSINT Entity Graph — {target_val}", fontsize=14, fontweight="bold")
  plt.axis("off")
  plt.tight_layout()
  plt.savefig(output_path, dpi=300, bbox_inches="tight")
  plt.close()
  return output_path
