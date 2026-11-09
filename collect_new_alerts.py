
import os
import sqlite3
import requests
import urllib3

from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
USERNAME = os.getenv("WAZUH_USERNAME")
PASSWORD = os.getenv("WAZUH_PASSWORD")

ALERT_LEVEL = int(os.getenv("ALERT_LEVEL", "5"))
DB_PATH = "soc_monitor.db"
INDEX_PATTERN = "wazuh-alerts-4.x-*"
PAGE_SIZE = 500


def fetch_and_store():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    total_fetched = 0
    new_count = 0
    duplicate_count = 0
    search_after = None

    try:
        while True:
            query = {
                "size": PAGE_SIZE,
                "sort": [
                    {"@timestamp": {"order": "asc"}},
                    {"_id": {"order": "asc"}}
                ],
                "query": {
                    "range": {
                        "rule.level": {"gte": ALERT_LEVEL}
                    }
                }
            }

            if search_after:
                query["search_after"] = search_after

            response = requests.post(
                f"{INDEXER_URL}/{INDEX_PATTERN}/_search",
                auth=HTTPBasicAuth(USERNAME, PASSWORD),
                json=query,
                verify=False,
                timeout=30
            )

            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])

            if not hits:
                break

            total_fetched += len(hits)

            for hit in hits:
                alert = hit.get("_source", {})
                rule = alert.get("rule", {})
                agent = alert.get("agent", {})

                result = cursor.execute("""
                    INSERT OR IGNORE INTO processed_alerts (
                        index_name, alert_id, agent_name,
                        rule_id, rule_level, alert_timestamp, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'pending')
                """, (
                    hit.get("_index"),
                    hit.get("_id"),
                    agent.get("name", "Unknown"),
                    str(rule.get("id", "Unknown")),
                    int(rule.get("level", 0)),
                    alert.get("@timestamp", "")
                ))

                if result.rowcount == 1:
                    new_count += 1
                    print(
                        f"[NEW] Rule {rule.get('id')} | "
                        f"Level {rule.get('level')} | "
                        f"Alert ID: {hit.get('_id')}"
                    )
                else:
                    duplicate_count += 1

            connection.commit()

            if len(hits) < PAGE_SIZE:
                break

            search_after = hits[-1]["sort"]

    finally:
        connection.close()

    print("\n========== COLLECTION SUMMARY ==========")
    print(f"Total fetched       : {total_fetched}")
    print(f"New alerts stored   : {new_count}")
    print(f"Duplicates skipped  : {duplicate_count}")
    print("=========================================")


if __name__ == "__main__":
    print("\n========== SOC ALERT COLLECTOR ==========\n")

    try:
        fetch_and_store()
    except requests.RequestException as error:
        print(f"[ERROR] Wazuh connection failed: {error}")
    except (sqlite3.Error, ValueError, TypeError, KeyError) as error:
        print(f"[ERROR] Processing failed: {error}")
