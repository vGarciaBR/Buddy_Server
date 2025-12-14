
import os

class Config:
    # Server Settings
    HOST = '0.0.0.0'
    PORT = 8355 # 8352 default, but Reg says 8355 (0x20A3)
    
    # Database Settings
    DB_HOST = '127.0.0.1'
    DB_USER = 'root'
    DB_PASS = ""
    DB_NAME = "gbwc"
    DB_PORT = 3306
    
    # Combined Dictionary for easier access
    DB_CONFIG = {
        'user': DB_USER,
        'password': DB_PASS,
        'host': DB_HOST,
        'database': DB_NAME,
        'port': DB_PORT
    }

    # Packet Settings
    HEADER_SIZE = 4 # Adjust based on actual protocol (usually 2 bytes len + 2 bytes ID or similar)
