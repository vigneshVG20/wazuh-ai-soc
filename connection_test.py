
import os
import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load configuration
indexer_url = os.getenv("WAZUH_INDEXER_URL")
username = os.getenv("WAZUH_USERNAME")
password = os.getenv("WAZUH_PASSWORD")

ollama_url = os.getenv("OLLAMA_URL")
ollama_model = os.getenv("OLLAMA_MODEL")

print("\n========== SOC AI CONNECTION TEST ==========\n")

# Test Wazuh Indexer
print("[1] Testing Wazuh Indexer...")

try:
    response = requests.get(
        indexer_url,
        auth=(username, password),
        verify=False,
        timeout=10
    )

    if response.status_code == 200:
        print("[SUCCESS] Wazuh Indexer connected!")
    else:
        print(f"[FAILED] Wazuh returned HTTP {response.status_code}")

except requests.RequestException as error:
    print(f"[FAILED] Wazuh connection error: {error}")

# Test Kali Ollama
print("\n[2] Testing Kali Ollama...")

try:
    response = requests.get(
        f"{ollama_url}/api/tags",
        timeout=10
    )

    response.raise_for_status()
    models = response.json().get("models", [])

    available_models = [model.get("name") for model in models]

    if ollama_model in available_models:
        print(f"[SUCCESS] Ollama connected! Model found: {ollama_model}")
    else:
        print(f"[WARNING] Ollama connected, but {ollama_model} was not found.")
        print("Available models:", available_models)

except requests.RequestException as error:
    print(f"[FAILED] Ollama connection error: {error}")

print("\n========== TEST COMPLETED ==========\n")
