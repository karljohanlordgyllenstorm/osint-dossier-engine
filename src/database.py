from datetime import datetime, timezone
import json
import sqlite3

DB_NAME = "osint_history.db"


def init_db():
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            target_type TEXT,
            timestamp TEXT,
            total_score INTEGER,
            severity TEXT,
            raw_data TEXT
        )
    """)
  conn.commit()
  conn.close()


def save_scan(gathered_data: dict, risk_report: dict):
  init_db()
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()

  target = gathered_data.get("target", {}).get("value", "unknown")
  target_type = gathered_data.get("target", {}).get("type", "unknown")
  timestamp = datetime.now(timezone.utc).isoformat()
  total_score = risk_report.get("total_score", 0)
  severity = risk_report.get("severity", "OKÄND")
  raw_data = json.dumps(gathered_data)

  cursor.execute(
      """
        INSERT INTO scans (target, target_type, timestamp, total_score, severity, raw_data)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
      (target, target_type, timestamp, total_score, severity, raw_data),
  )

  conn.commit()
  conn.close()


def get_scan_history(target: str):
  init_db()
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute(
      """
        SELECT timestamp, total_score, severity FROM scans
        WHERE target = ? ORDER BY timestamp DESC LIMIT 5
    """,
      (target,),
  )
  rows = cursor.fetchall()
  conn.close()
  return rows
