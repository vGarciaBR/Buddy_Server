
import mysql.connector
from config import Config

def inspect_db():
    print("Connecting to DB...")
    try:
        conn = mysql.connector.connect(**Config.DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # 1. Inspect User Table Columns
        print("\n--- Columns in 'User' Table ---")
        cursor.execute("DESCRIBE User")
        cols = cursor.fetchall()
        for c in cols:
            print(f"{c['Field']} ({c['Type']})")
            
        # 2. Inspect Sample Data from User
        print("\n--- Sample User Data (First 3) ---")
        cursor.execute("SELECT * FROM User LIMIT 3")
        rows = cursor.fetchall()
        for r in rows:
            print(r)
            
        # 3. Inspect BuddyList Table Columns
        print("\n--- Columns in 'BuddyList' Table ---")
        cursor.execute("DESCRIBE BuddyList")
        cols = cursor.fetchall()
        for c in cols:
            print(f"{c['Field']} ({c['Type']})")

        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    inspect_db()
