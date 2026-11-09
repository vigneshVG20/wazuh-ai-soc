
import os
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

# Search across all daily Wazuh alert indexes
INDEX_PATTERN = "wazuh-alerts-4.x-*"

query = {
    "size": 10,
    "sort": [
        {"@timestamp": {"order": "desc"}}
    ],
    "query": {
        "range": {
            "rule.level": {
                "gte": ALERT_LEVEL
            }
        }
    }
}

print("\n========== WAZUH ALERT FETCHER ==========\n")

try:
    response = requests.post(
        f"{INDEXER_URL}/{INDEX_PATTERN}/_search",
        auth=HTTPBasicAuth(USERNAME, PASSWORD),
        json=query,
        verify=False,
        timeout=20
    )

    response.raise_for_status()
    data = response.json()

    hits = data.get("hits", {}).get("hits", [])

    print(f"Alerts found (matching query): {data['hits']['total']}")
    print(f"Displaying latest {len(hits)} alerts with rule level >= {ALERT_LEVEL}\n")

    for number, hit in enumerate(hits, start=1):
        alert = hit.get("_source", {})
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        print(f"---------- ALERT {number} ----------")
        print(f"Unique document ID : {hit.get('_id')}")
        print(f"Index              : {hit.get('_index')}")
        print(f"Timestamp          : {alert.get('@timestamp')}")
        print(f"Agent              : {agent.get('name', 'Unknown')}")
        print(f"Rule ID            : {rule.get('id', 'Unknown')}")
        print(f"Rule Level         : {rule.get('level', 'Unknown')}")
        print(f"Description        : {rule.get('description', 'Unknown')}")
        print()

except requests.RequestException as error:
    print(f"[ERROR] Wazuh request failed: {error}")

except (ValueError, KeyError) as error:
    print(f"[ERROR] Could not process response: {error}")

print("========== FETCH COMPLETED ==========\n")
