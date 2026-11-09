
import os
import json
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DB_PATH = "soc_monitor.db"

import sqlite3

connection = sqlite3.connect(DB_PATH)
row = connection.execute("""
    SELECT index_name, alert_id
    FROM processed_alerts
    WHERE status = 'analyzed'
    LIMIT 1
""").fetchone()
connection.close()

if not row:
    print("No analyzed alert found.")
    raise SystemExit

index_name, alert_id = row

response = requests.get(
    f"{os.getenv('WAZUH_INDEXER_URL')}/{index_name}/_doc/{alert_id}",
    auth=HTTPBasicAuth(
        os.getenv("WAZUH_USERNAME"),
        os.getenv("WAZUH_PASSWORD")
    ),
    verify=False,
    timeout=20
)

response.raise_for_status()
alert = response.json()["_source"]

print("\n========== ORIGINAL WAZUH EVIDENCE ==========")
print("Available fields:", list(alert.keys()))

for field in ["rule", "data", "full_log", "decoder", "location"]:
    print(f"\n--- {field.upper()} ---")
    value = alert.get(field, "NOT PRESENT")
    print(json.dumps(value, indent=2)[:5000])

print("\n========== INSPECTION COMPLETED ==========")
