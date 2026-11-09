
import os
import time
import sqlite3
import requests
import urllib3

from datetime import datetime, timezone
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

from ai_analyzer import get_original_alert, analyze_with_ollama
from pdf_generator import generate_report
from email_sender import send_pdf_email

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =====================================================
# CONFIGURATION
# =====================================================

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
USERNAME = os.getenv("WAZUH_USERNAME")
PASSWORD = os.getenv("WAZUH_PASSWORD")

ALERT_LEVEL = int(os.getenv("ALERT_LEVEL", "5"))
CRITICAL_LEVEL = int(os.getenv("CRITICAL_EMAIL_LEVEL", "10"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))

DB_PATH = "soc_monitor.db"
INDEX_PATTERN = "wazuh-alerts-4.x-*"
PAGE_SIZE = 500


# =====================================================
# DATABASE INITIALIZATION
# =====================================================

def initialize_monitor_database():

    connection = sqlite3.connect(DB_PATH)

    columns = [
        row[1] for row in connection.execute(
            "PRAGMA table_info(processed_alerts)"
        )
    ]

    additions = {
        "automation_status": "TEXT DEFAULT 'queued'",
        "email_status": "TEXT DEFAULT 'pending'",
        "email_sent_at": "TEXT",
        "report_path": "TEXT",
        "automation_error": "TEXT"
    }

    for column, definition in additions.items():

        if column not in columns:

            connection.execute(
                f"ALTER TABLE processed_alerts "
                f"ADD COLUMN {column} {definition}"
            )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS monitor_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT
        )
    """)

    # First-run protection:
    # Existing alerts must never trigger a mass email.
    initialized = connection.execute("""
        SELECT setting_value
        FROM monitor_settings
        WHERE setting_key = 'historical_bootstrap'
    """).fetchone()

    if not initialized:

        connection.execute("""
            UPDATE processed_alerts
            SET automation_status = 'historical'
            WHERE automation_status = 'queued'
        """)

        connection.execute("""
            INSERT INTO monitor_settings
            (setting_key, setting_value)
            VALUES ('historical_bootstrap', 'complete')
        """)

        print("[INFO] Existing alerts marked as historical.")

    connection.commit()
    connection.close()

    print("[SUCCESS] Automation database ready.")


# =====================================================
# FETCH NEW WAZUH ALERTS
# =====================================================

def collect_new_alerts():

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    total_fetched = 0
    new_count = 0
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
                        "rule.level": {
                            "gte": ALERT_LEVEL
                        }
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

            hits = response.json().get(
                "hits", {}
            ).get("hits", [])

            if not hits:
                break

            total_fetched += len(hits)

            for hit in hits:

                alert = hit.get("_source", {})
                rule = alert.get("rule", {})
                agent = alert.get("agent", {})

                result = cursor.execute("""
                    INSERT OR IGNORE INTO processed_alerts (
                        index_name,
                        alert_id,
                        agent_name,
                        rule_id,
                        rule_level,
                        alert_timestamp,
                        status,
                        automation_status,
                        email_status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'pending',
                            'queued', 'pending')
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
                        f"[NEW ALERT] Rule {rule.get('id')} | "
                        f"Level {rule.get('level')} | "
                        f"Agent {agent.get('name')}"
                    )

            connection.commit()

            if len(hits) < PAGE_SIZE:
                break

            search_after = hits[-1]["sort"]

    finally:

        connection.close()

    print(
        f"[COLLECTOR] Fetched: {total_fetched} | "
        f"New: {new_count}"
    )

    return new_count


# =====================================================
# PROCESS CRITICAL ALERTS
# =====================================================


def process_critical_alerts():

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    try:
        alerts = connection.execute("""
            SELECT *
            FROM processed_alerts
            WHERE rule_level >= ?
              AND automation_status IN (
                  'queued', 'failed', 'analyzing'
              )
            ORDER BY alert_timestamp ASC
            LIMIT 5
        """, (CRITICAL_LEVEL,)).fetchall()

        if not alerts:
            print("[INFO] No new critical alerts.")
            return

        print(
            f"\n[CRITICAL] Alerts requiring processing: "
            f"{len(alerts)}"
        )

        for item in alerts:

            alert_id = item["alert_id"]
            index_name = item["index_name"]

            print("\n====================================")
            print(f"Processing alert: {alert_id}")
            print(f"Rule ID: {item['rule_id']}")
            print(f"Rule Level: {item['rule_level']}")
            print("====================================")

            try:
                connection.execute("""
                    UPDATE processed_alerts
                    SET automation_status = 'analyzing',
                        automation_error = NULL
                    WHERE index_name = ? AND alert_id = ?
                """, (index_name, alert_id))

                connection.commit()

                current = connection.execute("""
                    SELECT *
                    FROM processed_alerts
                    WHERE index_name = ? AND alert_id = ?
                """, (index_name, alert_id)).fetchone()

                # AI ANALYSIS
                if not current["ai_analysis"]:

                    print("[AI] Retrieving original Wazuh evidence...")

                    original_alert = get_original_alert(
                        index_name,
                        alert_id
                    )

                    print("[AI] Sending alert to Kali Ollama...")

                    analysis = analyze_with_ollama(original_alert)

                    connection.execute("""
                        UPDATE processed_alerts
                        SET ai_analysis = ?,
                            ai_analyzed_at = ?,
                            status = 'analyzed'
                        WHERE index_name = ? AND alert_id = ?
                    """, (
                        analysis,
                        datetime.now(timezone.utc).isoformat(),
                        index_name,
                        alert_id
                    ))

                    connection.commit()

                    print("[SUCCESS] AI analysis saved.")

                # REFRESH DATABASE RECORD
                current = connection.execute("""
                    SELECT *
                    FROM processed_alerts
                    WHERE index_name = ? AND alert_id = ?
                """, (index_name, alert_id)).fetchone()

                # PDF GENERATION
                pdf_path = current["report_path"]

                if not pdf_path or not os.path.isfile(pdf_path):

                    print("[PDF] Generating red SOC report...")

                    pdf_path = generate_report(current)

                    if not pdf_path:
                        raise RuntimeError("PDF generation failed.")

                    connection.execute("""
                        UPDATE processed_alerts
                        SET report_path = ?
                        WHERE index_name = ? AND alert_id = ?
                    """, (pdf_path, index_name, alert_id))

                    connection.commit()

                print(f"[PDF] Ready: {pdf_path}")

                # GMAIL DELIVERY
                print("[EMAIL] Sending critical alert report...")

                send_pdf_email(
                    pdf_path,
                    rule_id=current["rule_id"],
                    rule_level=current["rule_level"],
                    agent=current["agent_name"],
                    alert_id=alert_id
                )

                # RECORD SUCCESSFUL SMTP DELIVERY
                connection.execute("""
                    UPDATE processed_alerts
                    SET automation_status = 'emailed',
                        email_status = 'sent',
                        email_sent_at = ?,
                        automation_error = NULL
                    WHERE index_name = ? AND alert_id = ?
                """, (
                    datetime.now(timezone.utc).isoformat(),
                    index_name,
                    alert_id
                ))

                connection.commit()

                print("[SUCCESS] Critical PDF emailed to admin.")
                print("[SUCCESS] Alert delivery recorded.")

            except Exception as error:

                connection.execute("""
                    UPDATE processed_alerts
                    SET automation_status = 'failed',
                        automation_error = ?
                    WHERE index_name = ? AND alert_id = ?
                """, (
                    f"{type(error).__name__}: {error}"[:1000],
                    index_name,
                    alert_id
                ))

                connection.commit()

                print(f"[ERROR] Alert processing failed: {error}")
                print("[INFO] Will retry in a later monitoring cycle.")

    finally:
        connection.close()


# =====================================================
# CONTINUOUS MONITOR
# =====================================================

def start_monitor():

    print("\n")
    print("==============================================")
    print("       SOC AI AUTOMATIC MONITORING")
    print("==============================================")
    print(f"Wazuh collection threshold : {ALERT_LEVEL}")
    print(f"Critical email threshold  : {CRITICAL_LEVEL}")
    print(f"Polling interval          : {POLL_INTERVAL} seconds")
    print("AI engine                 : Kali Ollama Qwen3")
    print("PDF generation            : Windows ReportLab")
    print("Email delivery            : Gmail SMTP")
    print("==============================================\n")

    initialize_monitor_database()

    while True:

        try:

            print(
                f"\n[{datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')}] "
                "Starting monitoring cycle..."
            )

            collect_new_alerts()

            process_critical_alerts()

            print(
                f"\n[WAIT] Next monitoring cycle in "
                f"{POLL_INTERVAL} seconds."
            )

        except KeyboardInterrupt:

            print("\n[STOP] SOC monitoring stopped by user.")
            break

        except Exception as error:

            print(
                f"[MONITOR ERROR] "
                f"{type(error).__name__}: {error}"
            )

        try:
            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:

            print("\n[STOP] SOC monitoring stopped by user.")
            break


if __name__ == "__main__":
    start_monitor()
