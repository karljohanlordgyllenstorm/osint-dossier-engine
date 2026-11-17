import asyncio
import aiohttp
from datetime import datetime, timezone

async def fetch_bolagsverket_data(company_name_or_orgnr: str) -> dict:
    """
    Exempelstruktur för integration mot publika bolagsdata- och registertjänster.
    Anpassa endpoint och autentisering (t.ex. API-nyckel via headers) efter 
    det specifika register du ansluter till (Bolagsverket, Allabolag API etc.).
    """
    cleaned_query = company_name_or_orgnr.strip()
    
    # Exempel på headers för officiell API-nyckel om sådan används
    headers = {
        "User-Agent": "OSINT-Legal-Engine/1.6",
        "Accept": "application/json",
        # "Authorization": "Bearer DIN_API_NYCKEL_HÄR"
    }
    
    # Exempel-endpoint (ersätt med Bolagsverkets publika API- eller Open Data-url)
    api_url = f"https://api.bolagsverket.se/sok/v1/foretag?q={urllib_quote(cleaned_query)}"
    
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            # Timeout satt till 10 sekunder för att förhindra att pipelinen låser sig
            async with session.get(api_url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "source": "official_registry",
                        "status": "success",
                        "queried_target": cleaned_query,
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "registry_data": data
                    }
                else:
                    return {
                        "source": "official_registry",
                        "status": "error",
                        "code": resp.status,
                        "message": f"Kunde inte hämta data från register (HTTP {resp.status})"
                    }
    except Exception as e:
        return {
            "source": "official_registry",
            "status": "exception",
            "error": str(e)
        }

def urllib_quote(text: str) -> str:
    import urllib.parse
    return urllib.parse.quote(text)
