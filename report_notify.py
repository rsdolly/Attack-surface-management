import json
import csv
import pdfkit
import mysql.connector
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# Secure password retrieval (example using environment variable)
def get_secure_password():
    password = os.getenv("EMAIL_PASSWORD")
    if not password:
        raise ValueError("Email password not found in environment variables.")
    return password

# Save results to MySQL database
def save_to_mysql(data, table):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password=os.getenv("MYSQL_PASSWORD"),  # Secure password retrieval
            database="asm_results"
        )
        cursor = conn.cursor()

        if table == "technologies":
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS technologies (
                    target VARCHAR(255),
                    technology JSON
                )
            """)
            cursor.execute("INSERT INTO technologies (target, technology) VALUES (%s, %s)",
                           (data['target'], json.dumps(data['detected_technologies'])))

        elif table == "vulnerabilities":
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    target VARCHAR(255),
                    cves JSON,
                    exploits JSON,
                    ssl_misconfigurations JSON,
                    sensitive_files JSON,
                    outdated_technologies JSON
                )
            """)
            cursor.execute("INSERT INTO vulnerabilities (target, cves, exploits, ssl_misconfigurations, sensitive_files, outdated_technologies) VALUES (%s, %s, %s, %s, %s, %s)",
                           (data['target'], json.dumps(data['cves']), json.dumps(data['exploits']),
                            json.dumps(data['ssl_misconfigurations']), json.dumps(data['sensitive_files']),
                            json.dumps(data['outdated_technologies'])))

        elif table == "takeovers":
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS takeovers (
                    subdomain VARCHAR(255),
                    cname VARCHAR(255),
                    matched_cloud_service VARCHAR(255),
                    orphaned BOOLEAN,
                    date VARCHAR(255)
                )
            """)
            for entry in data:
                try:
                    cursor.execute("INSERT INTO takeovers (subdomain, cname, matched_cloud_service, orphaned, date) VALUES (%s, %s, %s, %s, %s)",
                                   (entry['subdomain'], entry['cname'], entry['matched_cloud_service'], entry['orphaned'], entry['date']))
                except mysql.connector.Error as insert_error:
                    print(f"[!] Error inserting takeover data: {insert_error}")

        conn.commit()

    except mysql.connector.Error as err:
        print(f"[!] MySQL Error: {err}")
    finally:
        if conn:
            conn.close()

# Generate CSV
def generate_csv(data, filename, fields=None): # Added fields parameter
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            if isinstance(data, list):
                if fields:
                    headers = fields
                    writer.writerow(headers)
                    for row in data:
                        writer.writerow([row.get(field) for field in fields])
                else:
                    headers = data[0].keys()
                    writer.writerow(headers)
                    for row in data:
                        writer.writerow(row.values())
            elif isinstance(data, dict):
                writer.writerow(['Key', 'Value'])
                for key, value in data.items():
                    writer.writerow([key, json.dumps(value)])
        print(f"[+] CSV saved as {filename}")
    except IOError as e:
        print(f"[!] CSV Generation Error: {e}")

# Generate JSON
def generate_json(data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[+] JSON saved as {filename}")
    except IOError as e:
        print(f"[!] JSON Generation Error: {e}")

# Generate PDF
def generate_pdf(data, filename):
    try:
        html = f"<pre>{json.dumps(data, indent=4)}</pre>" # Basic HTML
        pdfkit.from_string(html, filename)
        print(f"[+] PDF saved as {filename}")
    except Exception as e:
        print(f"[!] PDF Generation Error: {e}")

# Send Email Notification
def send_email_report(email, password, subject, body, attachments=None):
    msg = MIMEMultipart()
    msg['From'] = email
    msg['To'] = email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    # Add attachments (if any)
    if attachments:
        for filename in attachments:
            # ... (code to attach files)
            pass

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)  # Make configurable
        server.starttls()
        server.login(email, password)
        server.send_message(msg)
        server.quit()
        print("[+] Email sent successfully!")
    except smtplib.SMTPException as e:
        print(f"[!] Email sending failed: {e}")
    except Exception as e:
         print(f"[!] Email sending failed: {e}")

# Main Execution
def generate_reports_and_notify(fingerprint_result, vuln_result, takeover_result):
    domain = fingerprint_result['target']

    # Save to DB
    save_to_mysql(fingerprint_result, "technologies")
    save_to_mysql(vuln_result, "vulnerabilities")
    save_to_mysql(takeover_result, "takeovers")

    report_dir = "reports" # Make configurable
    os.makedirs(report_dir, exist_ok=True)

    # Generate Reports
    generate_json(fingerprint_result, os.path.join(report_dir, f"{domain}_tech.json"))
    generate_json(vuln_result, os.path.join(report_dir, f"{domain}_vuln.json"))
    generate_json(takeover_result, os.path.join(report_dir, f"{domain}_takeover.json"))

    generate_csv(fingerprint_result['detected_technologies'], os.path.join(report_dir, f"{domain}_tech.csv"))
    generate_csv(vuln_result, os.path.join(report_dir, f"{domain}_vuln.csv"))
    generate_csv(takeover_result, os.path.join(report_dir, f"{domain}_takeover.csv"))

    generate_pdf(fingerprint_result, os.path.join(report_dir, f"{domain}_tech.pdf"))
    generate_pdf(vuln_result, os.path.join(report_dir, f"{domain}_vuln.pdf"))
    generate_pdf(takeover_result, os.path.join(report_dir, f"{domain}_takeover.pdf"))

    # Send Alert if any critical issue
    if vuln_result.get('cves') or any(x.get('orphaned') for x in takeover_result):
        email = input("Enter your email for alerting: ")
        try:
            password = get_secure_password() # Retrieve password securely
            subject = f"[ALERT] Issues found on {domain}"
            body = f"Potential issues found:\nCVEs: {len(vuln_result.get('cves', []))}\nTakeovers: {len([x for x in takeover_result if x.get('orphaned')])}"
            send_email_report(email, password, subject, body, attachments=[os.path.join(report_dir, f"{domain}_vuln.json")]) # Example attaching vuln report
        except ValueError as e:
            print(f"[!] Error: {e}")
        except Exception as e:
            print(f"[!] Error sending email: {e}")