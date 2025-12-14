import mysql.connector

# Connect to database
conn = mysql.connector.connect(
    host='127.0.0.1',
    user='root',
    password='',
    database='gbwc'
)

cursor = conn.cursor(dictionary=True)

# Get all offline messages
query = "SELECT * FROM Packet"
cursor.execute(query)
packets = cursor.fetchall()

print(f"\n=== TOTAL OFFLINE MESSAGES: {len(packets)} ===\n")

for pkt in packets:
    print(f"SerialNo: {pkt['SerialNo']}")
    print(f"Sender: {pkt['Sender']}")
    print(f"Receiver: {pkt['Receiver']}")
    print(f"Code: {hex(pkt['Code'])}")
    print(f"Body (first 50 chars): {pkt['Body'][:50]}...")
    print(f"Time: {pkt['Time']}")
    print("-" * 60)

cursor.close()
conn.close()
