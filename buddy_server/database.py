import mysql.connector
from mysql.connector import Error
from .config import Config

class Database:
    def __init__(self, db_config):
        self.db_config = db_config
        self.connection = None

    def connect(self):
        try:
            self.connection = mysql.connector.connect(**self.db_config)
            if self.connection.is_connected():
                self.connection.autocommit = True  # Enable autocommit
                print("Database connected successfully")
                return True
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            return False
            if self.connection.is_connected():
                print("Connected to MySQL database")
        except Error as e:
            print(f"Error while connecting to MySQL: {e}")

    def disconnect(self):
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("MySQL connection is closed")

    def get_user_game_data(self, user_id):
        """
        Fetches the complete game header for a user.
        Based on binary analysis:
        SELECT Guild, TotalGrade, SeasonGrade, MemberCount, TotalRank, SeasonRank, GuildRank, 
        AccumShot, AccumDamage, TotalScore, SeasonScore, Money, EventScore0, EventScore1, ...
        FROM Game WHERE Id='%s'
        """
        cursor = self.connection.cursor(dictionary=True)
        query = """
            SELECT Guild, TotalGrade, SeasonGrade, MemberCount, TotalRank, SeasonRank, GuildRank, 
                   AccumShot, AccumDamage, TotalScore, SeasonScore, Money, 
                   EventScore0, EventScore1, EventScore2, EventScore3, 
                   Country, CountryGrade, CountryRank 
            FROM Game WHERE Id = %s
        """
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        cursor.close()
        return result

    def get_user_by_nickname(self, nickname):
        cursor = self.connection.cursor(dictionary=True)
        query = "SELECT Id, Nickname FROM User WHERE Nickname = %s"
        cursor.execute(query, (nickname,))
        result = cursor.fetchone()
        cursor.close()
        return result

    def resolve_user_id(self, login_name):
        """
        Tries to resolve the string login name (e.g. 'teste') to the correct User ID for foreign keys.
        If the DB expects Integers for 'Id' in other tables, we must find the numeric ID here.
        """
        cursor = self.connection.cursor(dictionary=True)
        try:
            # 1. Try treating login_name as the ID (if Id is valid)
            # But we know BuddyList expects Int.
            # So maybe 'Id' in User is NOT the login name, but the numeric ID?
            # And there is another column for login?
            
            # Let's try to find a user where 'Id' (as string) matches, OR 'Login' matches.
            # Since we don't know column names, let's try 'Id' first.
            # If 'Id' is INT, querying WHERE Id='teste' will fail or implicit cast to 0.
            
            # SAFE QUERY: Check columns first? Too slow.
            # Let's try to fetch by Nickname first, assuming Login ~= Nickname for 'teste'.
            query = "SELECT Id FROM User WHERE Nickname = %s"
            cursor.execute(query, (login_name,))
            res = cursor.fetchone()
            if res:
                return res['Id']

            # Try by 'Login' column
            try:
                query_login = "SELECT Id FROM User WHERE Login = %s"
                cursor.execute(query_login, (login_name,))
                res = cursor.fetchone()
                if res:
                    return res['Id']
            except Error:
                # Login column might not exist or be named differently (e.g. Username)
                pass

            return login_name 
            
        except Error as e:
            print(f"Error resolving user ID: {e}")
            return login_name
        finally:
            cursor.close()

    def get_current_user_location(self, user_id):
        """
        Checks if a user is online and where.
        Query from binary: SELECT Context, ServerIP, ServerPort FROM CurrentUser WHERE Id='%s'
        """
        cursor = self.connection.cursor(dictionary=True)
        query = "SELECT Context, ServerIP, ServerPort FROM CurrentUser WHERE Id = %s"
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        cursor.close()
        return result

    def check_game_context(self, user_id):
        """
        Verifica se o usuário está em contexto de jogo (Context != 0/Lobby).
        Baseado na análise do GunboundServ.exe que faz REPLACE CurrentUser ... Context=...
        Retorna True se estiver em jogo.
        """
        loc = self.get_current_user_location(user_id)
        if loc and loc.get('Context', 0) > 1: # Assumindo 0=Lobby, 1=RoomWait, 2=Game? 
             # Na dúvida, se tem contexto e ServerPort > 0, está conectado num GameServer.
             return True
        return False

    def login_log(self, user_id, ip, port, server_ip, server_port, country):
        """
        Logs a user login.
        Query: INSERT INTO LoginLog (Id, Ip, Ip_v, Port, Port_v, Time, ServerIp, ServerPort, Country) VALUES ...
        """
        cursor = self.connection.cursor()
        query = """
            INSERT INTO LoginLog (Id, Ip, Ip_v, Port, Port_v, Time, ServerIp, ServerPort, Country) 
            VALUES (%s, %s, 0, %s, 0, NOW(), %s, %s, %s)
        """
        # Ip_v and Port_v might be virtual IPs/Ports, setting to 0 for now
        cursor.execute(query, (user_id, ip, port, server_ip, server_port, country))
        self.connection.commit()
        cursor.close()

    
    # -------------------------------------------------------------------------
    # ANALYZED QUERIES (BuddyServ2.exe)
    # -------------------------------------------------------------------------
    
    # -------------------------------------------------------------------------
    # ID MAPPING (Login String <-> UserNo Int)
    # -------------------------------------------------------------------------
    def get_userno(self, login_id):
        """Converts Login ID (String) to UserNo (Int)."""
        cursor = self.connection.cursor()
        # Assuming 'Id' is the login column and 'N' is the numeric ID based on debug output.
        query = "SELECT N FROM User WHERE Id = %s" 
        cursor.execute(query, (login_id,))
        res = cursor.fetchone()
        cursor.close()
        if res:
            return res[0]
        return None

    def get_login_id(self, userno):
        """Converts UserNo (Int) to Login ID (String)."""
        cursor = self.connection.cursor()
        query = "SELECT Id FROM User WHERE N = %s"
        cursor.execute(query, (userno,))
        res = cursor.fetchone()
        cursor.close()
        if res:
            return res[0]
        return str(userno)

    # -------------------------------------------------------------------------
    # BUDDY LIST OPERATIONS (With Conversion)
    # -------------------------------------------------------------------------
    
    def add_buddy(self, user_id, friend_id):
        # user_id and friend_id are STRINGS (Logins).
        # We must convert to INTs for DB.
        
        u_no = self.get_userno(user_id)
        f_no = self.get_userno(friend_id)
        
        if not u_no or not f_no:
            print(f"Cannot add buddy: UserNo not found for {user_id} or {friend_id}")
            return False

        cursor = self.connection.cursor()
        try:
            # Check if exists (Using Ints)
            check_query = "SELECT * FROM BuddyList WHERE Id = %s AND Buddy = %s"
            cursor.execute(check_query, (u_no, f_no))
            if cursor.fetchone():
                cursor.close()
                return False

            query = "INSERT INTO BuddyList (Id, Buddy, Category) VALUES (%s, %s, %s)"
            cursor.execute(query, (u_no, f_no, 'General'))
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error adding buddy: {e}")
            return False

    def remove_buddy(self, user_id, friend_id):
        u_no = self.get_userno(user_id)
        f_no = self.get_userno(friend_id)
        
        if not u_no or not f_no:
            return False

        cursor = self.connection.cursor()
        try:
            query = "DELETE FROM BuddyList WHERE Id = %s AND Buddy = %s"
            cursor.execute(query, (u_no, f_no))
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error removing buddy: {e}")
            return False
            
    
    def get_buddy_list(self, user_id):
        """
        Legacy wrapper for backward compatibility.
        Returns list of dicts: [{'friend_id': 'login'}, ...]
        """
        full_list = self.get_full_buddy_list(user_id)
        # Convert to old format
        simple_list = []
        for f in full_list:
            # map 'Id' or 'Nickname' to 'friend_id' depending on what legacy code expected
            # Legacy code expected 'friend_id' (login)
            simple_list.append({'friend_id': f['Id'], 'Category': f['Category']})
        return simple_list

    def get_full_buddy_list(self, user_id):
        """
        Retrieves the complete buddy list with details using a single JOIN query.
        Matches binary behavior: 
        SELECT u.Nickname, b.Category, u.Id
        FROM User AS u 
        INNER JOIN BuddyList AS b ON u.N = b.Buddy 
        WHERE b.Id = (SELECT N FROM User WHERE Id = %s)
        """
        cursor = self.connection.cursor(dictionary=True)
        try:
            # First, get the UserNo (N) for the requester
            u_no = self.get_userno(user_id)
            if not u_no:
                return []
                
            # Now fetch friends joining User table to get Nicknames directly
            # Assuming 'b.Buddy' is the UserNo of the friend
            query = """
                SELECT u.Id, u.Nickname, b.Category 
                FROM User AS u 
                INNER JOIN BuddyList AS b ON u.N = b.Buddy 
                WHERE b.Id = %s
            """
            cursor.execute(query, (u_no,))
            results = cursor.fetchall()
            return results
        except Error as e:
            print(f"Error fetching full buddy list: {e}")
            return []
        finally:
            cursor.close()

    def get_users_info(self, user_ids):
        # Deprecated logic kept for fallback, but get_full_buddy_list is preferred
        if not user_ids: return []
        format_strings = ','.join(['%s'] * len(user_ids))
        cursor = self.connection.cursor(dictionary=True)
        query = f"SELECT Id, Nickname FROM User WHERE Id IN ({format_strings})"
        cursor.execute(query, tuple(user_ids))
        res = cursor.fetchall()
        cursor.close()
        return res

    # -------------------------------------------------------------------------
    # OFFLINE PACKET HANDLING (Analyzed from BuddyServ2)
    # -------------------------------------------------------------------------
    
    def save_packet(self, sender_id, receiver_id, code, body):
        print(f"[DEBUG] save_packet called: sender={sender_id}, receiver={receiver_id}, code={hex(code)}")
        
        # Packet/OfflineMsg likely uses Ints too based on logs.
        s_no = self.get_userno(sender_id)
        r_no = self.get_userno(receiver_id)
        
        print(f"[DEBUG] Resolved UserNos: send={s_no}, recv={r_no}")
        
        if not s_no or not r_no:
            print(f"[ERROR] Cannot save packet: UserNo not found (s={s_no}, r={r_no})")
            return False
            
        cursor = self.connection.cursor()
        try:
            query = """
                INSERT INTO Packet (Receiver, Sender, Code, Body, Time) 
                VALUES (%s, %s, %s, %s, NOW())
            """
            print(f"[DEBUG] Executing INSERT: recv={r_no}, send={s_no}, code={code}, body_len={len(body)}")
            cursor.execute(query, (r_no, s_no, code, body))
            self.connection.commit()
            print(f"[SUCCESS] Comitted to database!")
            cursor.close()
            print(f"Saved offline packet from {sender_id}({s_no}) to {receiver_id}({r_no})")
            return True
        except Error as e:
            print(f"[ERROR] Error saving offline packet: {e}")
            return False

    def get_packets(self, receiver_id):
        r_no = self.get_userno(receiver_id)
        print(f"DEBUG: Checking offline packets for {receiver_id} (UserNo: {r_no})")
        if not r_no:
            return []
            
        cursor = self.connection.cursor(dictionary=True)
        query = """
            SELECT SerialNo, Sender, Code, Body 
            FROM Packet WHERE Receiver = %s ORDER BY SerialNo ASC
        """
        cursor.execute(query, (r_no,))
        packets_raw = cursor.fetchall()
        print(f"DEBUG: Found {len(packets_raw)} packets.")
        
        # Convert Sender (Int) back to String
        final_packets = []
        for p in packets_raw:
            sender_no = p['Sender']
            # Sometimes sender might be textual if legacy? Assuming Int based on error.
            # If sender column is Int, get_login_id.
            p['Sender'] = self.get_login_id(sender_no)
            final_packets.append(p)
            
        cursor.close()
        return final_packets

    def delete_packet(self, serial_no):
        """
        Deletes a specific packet after delivery.
        """
        cursor = self.connection.cursor()
        try:
            query = "DELETE FROM Packet WHERE SerialNo = %s"
            cursor.execute(query, (serial_no,))
            self.connection.commit()
            cursor.close()
        except Error as e:
            print(f"Error deleting packet {serial_no}: {e}")

    
    # -------------------------------------------------------------------------
    # GROUP MANAGEMENT
    # -------------------------------------------------------------------------
    def move_buddy_to_group(self, user_id, friend_id, new_category):
        """
        Moves a friend to a different category/group.
        Query: UPDATE BuddyList SET Category='%s' WHERE Id='%s' AND Buddy='%s'
        """
        cursor = self.connection.cursor()
        try:
            query = "UPDATE BuddyList SET Category = %s WHERE Id = %s AND Buddy = %s"
            cursor.execute(query, (new_category, user_id, friend_id))
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error moving buddy: {e}")
            return False

    def rename_group(self, user_id, old_category, new_category):
        """
        Renames an entire group of friends.
        Query: UPDATE BuddyList SET Category='%s' WHERE Id='%s' AND Category='%s'
        """
        cursor = self.connection.cursor()
        try:
            query = "UPDATE BuddyList SET Category = %s WHERE Id = %s AND Category = %s"
            cursor.execute(query, (new_category, user_id, old_category))
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error renaming group: {e}")
            return False
            
    # -------------------------------------------------------------------------
    # SEARCH & UTILS (Enhanced with Phone Support)
    # -------------------------------------------------------------------------
    def get_user_by_search_term(self, term):
        """
        Searches for a user by Nickname OR Phone Number.
        Binary string: DB] DBIN_ID_FROM_PHONE -> SELECT Id, Nickname FROM User WHERE Phone_number='%s'
        """
        cursor = self.connection.cursor(dictionary=True)
        # Try finding by Nickname first
        query = "SELECT Id, Nickname FROM User WHERE Nickname = %s"
        cursor.execute(query, (term,))
        res = cursor.fetchone()
        
        if not res:
            # If not found, try Phone Number
            # Note: The column 'Phone_number' is derived from the binary string.
            # Make sure this column exists in your User table schema!
            try:
                # We use parameterized query, but logic is "Phone_number = %s"
                query_phone = "SELECT Id, Nickname FROM User WHERE Phone_number = %s"
                cursor.execute(query_phone, (term,))
                res = cursor.fetchone()
            except Error:
                # Column might not exist in some DB versions, harmless fallback.
                pass
                
        cursor.close()
        return res

    def check_user_exists(self, nickname):
        # Kept for backward compat, but redirects to enhanced search
        return self.get_user_by_search_term(nickname)
