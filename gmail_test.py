
import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
APP_PASSWORD = "".join(
    os.getenv("SENDER_APP_PASSWORD", "").split()
)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")


def test_gmail():
    required = [
        SMTP_SERVER,
        SENDER_EMAIL,
        APP_PASSWORD,
        ADMIN_EMAIL
    ]

    if not all(required):
        print("[ERROR] Missing Gmail settings in .env")
        return

    message = EmailMessage()
    message["Subject"] = "SOC AI Monitor - Gmail Connection Test"
    message["From"] = SENDER_EMAIL
    message["To"] = ADMIN_EMAIL

    message.set_content("""
Hello,

Your Wazuh SOC AI monitoring system has successfully
connected to Gmail SMTP.

System: Wazuh + Ollama Qwen3
Email Service: Gmail SMTP
Status: Connection test successful

This is a test email. No security alert is being reported.

Regards,
SOC AI Monitoring System
""")

    try:
        print("[INFO] Connecting to Gmail SMTP...")

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.send_message(message)

        print("[SUCCESS] Gmail SMTP authentication successful!")
        print(f"[SUCCESS] Test email sent to: {ADMIN_EMAIL}")

    except Exception as error:
        print(f"[ERROR] Gmail test failed: {type(error).__name__}: {error}")


if __name__ == "__main__":
    test_gmail()
