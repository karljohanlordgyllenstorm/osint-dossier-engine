from duckduckgo_search import DDGS
import time

def fetch_property_data(target_name: str) -> dict:
    """
    Sök efter fastighetsinnehav och inskrivningar kopplat till målet 
    via publika register och sökindexering.
    """
    try:
        with DDGS() as ddgs:
            queries = [
                f'"{target_name}" site:lantmateriet.se',
                f'"{target_name}" fastighet OR lagfart OR tomträtt',
                f'"{target_name}" site:allabolag.se fastighet'
            ]
            results = []
            seen = set()
            
            for q in queries:
                time.sleep(0.8)
                res = list(ddgs.text(q, region="se-se", safesearch="moderate", max_results=5))
                for r in res:
                    href = r.get("href", "")
                    if href not in seen:
                        seen.add(href)
                        results.append(r)
                        
            return {
                "source": "property_registry_osint",
                "query": target_name,
                "results": results[:10]
            }
    except Exception as e:
        return {"source": "property_registry_osint", "error": str(e), "results": []}
