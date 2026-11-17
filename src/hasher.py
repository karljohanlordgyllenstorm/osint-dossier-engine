from datetime import datetime, timezone
import hashlib
import json


def generate_evidence_hash(data: dict) -> dict:
  """Skapar en kryptografisk SHA-256-hash och UTC-tidsstämpel för en datapunkt

  för att garantera spårbarhet och äkthet (Chain of Custody).
  """
  json_str = json.dumps(data, sort_keys=True, default=str)
  data_hash = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
  timestamp = datetime.now(timezone.utc).isoformat()

  return {
      "timestamp_utc": timestamp,
      "sha256_hash": data_hash,
      "verified_payload": data,
  }
