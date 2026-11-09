
import os
import requests
from requests.auth import HTTPBasicAuth
from getpass import getpass
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = os.getenv("WAZUH_INDEXER_URL")
INDEX = os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-4.x-*")
USERNAME = os.getenv("WAZUH_USERNAME")

if not all([URL, USERNAME]):
    print("[ERROR] Missing Wazuh settings in .env")
    raise SystemExit(1)

password = getpass("Indexer password: ")

query = {
    "size": 5,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {"match_all": {}}
}

response = requests.post(
    f"{URL}/{INDEX}/_search",
    auth=HTTPBasicAuth(USERNAME, password),
    json=query,
    verify=False,
    timeout=20
)

print("HTTP Status:", response.status_code)
response.raise_for_status()

data = response.json()

print("\nTotal alerts:", data["hits"]["total"]["value"])

for hit in data["hits"]["hits"]:
    alert = hit["_source"]
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    print("\n-----------------------------")
    print("Timestamp:", alert.get("@timestamp"))
    print("Agent:", agent.get("name"))
    print("Rule ID:", rule.get("id"))
    print("Level:", rule.get("level"))
    print("Description:", rule.get("description"))
    print("Event:", alert.get("full_log", "")[:300])
