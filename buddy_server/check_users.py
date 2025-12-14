import mysql.connector

conn = mysql.connector.connect(
    host='127.0.0.1',
    user='root',
    password='',
    database='gbwc'
)

cursor = conn.cursor(dictionary=True)

# Check if users exist
test_users = ['teste', 'teste2', 'TESTE']
for user in test_users:
    query = "SELECT N, Id, Nickname FROM User WHERE Id = %s"
    cursor.execute(query, (user,))
    result = cursor.fetchone()
    if result:
        print(f"[OK] User '{user}' found: N={result['N']}, Id={result['Id']}, Nick={result['Nickname']}")
    else:
        print(f"[FAIL] User '{user}' NOT FOUND")

cursor.close()
conn.close()
