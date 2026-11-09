
import os
import smtplib
from pathlib import Path
from email.message import EmailMessage
from email.utils import formatdate
from dotenv import load_dotenv

load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
APP_PASSWORD = "".join(
    os.getenv("SENDER_APP_PASSWORD", "").split()
)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")


def create_alert_email(rule_id, rule_level, agent, alert_id, pdf_name):
    critical = int(rule_level) >= 7

    if critical:
        accent = "#dc2626"
        background = "#fff1f2"
        status = "CRITICAL SECURITY ALERT"
        headline = "ALERT"
        message = "A critical Wazuh security alert has been detected."
    else:
        accent = "#2563eb"
        background = "#eff6ff"
        status = "SECURITY NOTIFICATION"
        headline = "SECURITY REPORT"
        message = "A Wazuh security alert report is ready."

    return f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:25px;background:#eef2f7;
                 font-family:Arial,Helvetica,sans-serif;">

      <div style="max-width:620px;margin:auto;background:#ffffff;
                  border-radius:12px;overflow:hidden;
                  border:1px solid #dbe2ea;">

        <div style="background:#111827;padding:28px;
                    text-align:center;">
          <div style="color:#cbd5e1;font-size:12px;
                      letter-spacing:3px;">
            SECURITY OPERATIONS CENTER
          </div>

          <h1 style="color:{accent};font-size:48px;
                     margin:16px 0 5px;font-weight:900;
                     letter-spacing:3px;">
            {headline}
          </h1>

          <div style="color:#ffffff;font-size:14px;
                      font-weight:bold;">
            {status}
          </div>
        </div>

        <div style="padding:25px;">

          <div style="background:{background};
                      border-left:5px solid {accent};
                      padding:17px;border-radius:6px;">
            <div style="color:{accent};font-size:12px;
                        font-weight:bold;letter-spacing:1px;">
              {status}
            </div>
            <p style="color:#1f2937;font-size:16px;
                      margin-bottom:0;">
              {message}
            </p>
          </div>

          <h2 style="color:#111827;font-size:18px;
                     margin-top:28px;">
            Alert Information
          </h2>

          <table style="width:100%;border-collapse:collapse;
                        font-size:14px;">
            <tr>
              <td style="padding:12px;background:#f8fafc;
                         color:#64748b;">Wazuh Rule ID</td>
              <td style="padding:12px;font-weight:bold;
                         color:#111827;">{rule_id}</td>
            </tr>
            <tr>
              <td style="padding:12px;background:#f8fafc;
                         color:#64748b;">Rule Level</td>
              <td style="padding:12px;font-weight:bold;
                         color:{accent};">{rule_level}</td>
            </tr>
            <tr>
              <td style="padding:12px;background:#f8fafc;
                         color:#64748b;">Agent</td>
              <td style="padding:12px;color:#111827;">{agent}</td>
            </tr>
            <tr>
              <td style="padding:12px;background:#f8fafc;
                         color:#64748b;">Alert ID</td>
              <td style="padding:12px;color:#111827;
                         word-break:break-all;">{alert_id}</td>
            </tr>
          </table>

          <div style="margin-top:25px;padding:18px;
                      border:1px solid #e2e8f0;
                      border-radius:8px;">
            <div style="font-size:15px;font-weight:bold;
                        color:#111827;">
              Security Incident Report Attached
            </div>
            <p style="font-size:13px;color:#64748b;
                      line-height:1.6;">
              The detailed PDF includes the original Wazuh
              evidence, AI-assisted findings, potential risks
              and recommended investigation steps.
            </p>
            <div style="color:{accent};font-size:13px;
                        font-weight:bold;">
              PDF: {pdf_name}
            </div>
          </div>

          <p style="font-size:12px;color:#64748b;
                    line-height:1.6;margin-top:25px;">
            AI-generated analysis is advisory. Verify the
            original Wazuh evidence before taking remediation
            actions. No security action was automatically
            executed.
          </p>
        </div>

        <div style="background:#111827;padding:20px;
                    text-align:center;">
          <div style="color:#ffffff;font-weight:bold;
                      font-size:13px;">
            SOC AI MONITORING SYSTEM
          </div>
          <div style="color:#94a3b8;font-size:11px;
                      margin-top:7px;">
            Automated Security Alert Notification
          </div>
        </div>

      </div>
    </body>
    </html>
    """


def send_pdf_email(
    pdf_path,
    rule_id="N/A",
    rule_level=0,
    agent="Unknown",
    alert_id="N/A",
    recipient=None
):
    pdf_path = Path(pdf_path)

    if not pdf_path.is_file():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")

    recipient = recipient or ADMIN_EMAIL

    if not all([SENDER_EMAIL, APP_PASSWORD, recipient]):
        raise ValueError("Missing email configuration in .env")

    message = EmailMessage()

    critical = int(rule_level) >= 7

    message["Subject"] = (
        f"[CRITICAL ALERT] Wazuh Level {rule_level} - Rule {rule_id}"
        if critical else
        f"[SOC REPORT] Wazuh Rule {rule_id}"
    )

    message["From"] = SENDER_EMAIL
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)

    message.set_content(
        f"Wazuh security report attached. "
        f"Rule ID: {rule_id}, Rule Level: {rule_level}."
    )

    message.add_alternative(
        create_alert_email(
            rule_id, rule_level, agent, alert_id, pdf_path.name
        ),
        subtype="html"
    )

    message.add_attachment(
        pdf_path.read_bytes(),
        maintype="application",
        subtype="pdf",
        filename=pdf_path.name
    )

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(message)

    print(f"[SUCCESS] Email sent to: {recipient}")
    print(f"[SUCCESS] PDF attached: {pdf_path.name}")


if __name__ == "__main__":
    import sqlite3

    connection = sqlite3.connect("soc_monitor.db")
    connection.row_factory = sqlite3.Row

    alert = connection.execute("""
        SELECT *
        FROM processed_alerts
        WHERE status = 'analyzed'
          AND ai_analysis IS NOT NULL
        ORDER BY ai_analyzed_at DESC
        LIMIT 1
    """).fetchone()

    connection.close()

    if not alert:
        print("[ERROR] No analysed alert found.")
    else:
        try:
            from pathlib import Path

            reports = list(Path("reports").glob("*.pdf"))

            if not reports:
                print("[ERROR] No PDF available.")
            else:
                latest_pdf = max(
                    reports, key=lambda p: p.stat().st_mtime
                )

                send_pdf_email(
                    latest_pdf,
                    rule_id=alert["rule_id"],
                    rule_level=alert["rule_level"],
                    agent=alert["agent_name"],
                    alert_id=alert["alert_id"]
                )

        except Exception as error:
            print(f"[ERROR] {type(error).__name__}: {error}")
