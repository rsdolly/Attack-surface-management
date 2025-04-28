import mysql.connector
from mysql.connector import Error
import json

def create_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="mysqlroot",
            database="asm_db"
        )
        return conn
    except Error as e:
        print(f"[!] MySQL connection error: {e}")
        return None

def initialize_db():
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                target_url VARCHAR(255),
                module_name VARCHAR(255),
                finding_type VARCHAR(255),
                data JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            print("[+] Database table 'findings' initialized.")
        except Error as e:
            print(f"[!] Failed to create table: {e}")
        conn.close()

def store_findings_mysql(target_url, module_name, finding_type, data_dict):
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO findings (target_url, module_name, finding_type, data) VALUES (%s, %s, %s, %s)",
                (target_url, module_name, finding_type, json.dumps(data_dict))
            )
            conn.commit()
            print(f"[+] Stored {finding_type} from {module_name} for {target_url} into database.")
        except Error as e:
            print(f"[!] Failed to store finding: {e}")
        conn.close()

if __name__ == "__main__":
    initialize_db()
