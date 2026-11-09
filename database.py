
import sqlite3

DB_PATH = "soc_monitor.db"

def initialize_database():
    connection = sqlite3.connect(DB_PATH)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS processed_alerts (
            index_name TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            agent_name TEXT,
            rule_id TEXT,
            rule_level INTEGER,
            alert_timestamp TEXT,
            status TEXT DEFAULT 'pending',
            processed_at TEXT,
            report_path TEXT,
            error_message TEXT,
            PRIMARY KEY (index_name, alert_id)
        )
    """)

    connection.commit()
    connection.close()

    print("[SUCCESS] SQLite database initialized!")
    print("[SUCCESS] Duplicate prevention table created!")

def check_database():
    connection = sqlite3.connect(DB_PATH)

    cursor = connection.execute(
        "SELECT COUNT(*) FROM processed_alerts"
    )

    count = cursor.fetchone()[0]

    connection.close()

    print(f"[INFO] Currently stored alerts: {count}")

if __name__ == "__main__":
    initialize_database()
    check_database()
