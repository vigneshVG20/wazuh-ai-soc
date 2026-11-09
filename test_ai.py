
import os
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_URL")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL")

def analyze_alert(alert):
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {
    "role": "system",
    "content": """
You are an experienced SOC Level 1 security analyst.

Analyze Wazuh security alerts accurately.

STRICT RULES:
1. Never change or invent the Wazuh rule ID or rule level.
2. Do not call an event an attack without sufficient evidence.
3. Clearly separate confirmed facts from possible risks.
4. Explain what happened in simple professional English.
5. Recommend practical investigation steps.
6. Do not invent usernames, IP addresses, timestamps, or evidence.
7. If information is missing, explicitly mention it.

Use this format:

1. Alert Summary
2. Confirmed Findings
3. Potential Security Risks
4. Recommended Investigation
5. SOC Analyst Conclusion

Be concise and professional.
"""
},
            {
                "role": "user",
                "content": str(alert)
            }
        ],
        "stream": False,
        "think": False
    }

    response = requests.post(
        f"{OLLAMA_URL.rstrip('/')}/api/chat",
        json=payload,
        timeout=180
    )

    response.raise_for_status()

    result = response.json()
    return result["message"]["content"]


sample_alert = {
    "agent": "example-endpoint",
    "rule_id": "5557",
    "severity": 5,
    "description": "unix_chkpwd: Password check failed",
    "location": "/var/log/auth.log"
}

if __name__ == "__main__":
    if not all([OLLAMA_URL, OLLAMA_MODEL]):
        print("[ERROR] Missing Ollama settings in .env")
        raise SystemExit(1)

    print("Sending sample Wazuh alert to Ollama...\n")

    analysis = analyze_alert(sample_alert)

    print("AI SECURITY ANALYSIS")
    print("====================")
    print(analysis)
