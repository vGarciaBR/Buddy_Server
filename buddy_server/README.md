# 🎮 GunBound Buddy Server - P2P Hybrid Edition

A chat and buddy system server for GunBound World Champion, implemented in Python with P2P (Peer-to-Peer) and hybrid relay support.

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Communication Protocol](#-communication-protocol)
- [Project Structure](#-project-structure)
- [Development](#-development)

## 🎯 Overview

The **Buddy Server** is an essential component of GunBound private server infrastructure. It manages:

- Buddy List system (Friends)
- Private chat between players
- Game invite system
- User status (Online, Busy, Playing, etc.)
- Offline messages
- Optimized P2P connections to reduce latency

This server was developed through reverse engineering of the original GunBound protocol, with modern improvements like hybrid P2P support.

## ✨ Features

### Core Features
- ✅ **User Authentication** - Secure login integrated with MySQL database
- ✅ **Buddy System** - Add, remove and organize friends in groups
- ✅ **Private Chat** - Real-time messaging between players
- ✅ **Offline Messages** - Storage and delivery of messages when recipient is offline
- ✅ **Invite System** - Send, accept and reject game invites
- ✅ **Status Management** - States: Online, Busy, Away, Playing, etc.

### Advanced Features
- 🔗 **Hybrid P2P** - Automatic direct connection attempt between clients, with relay fallback
- 📊 **Real-time Statistics** - Monitoring of connections, messages and P2P success rate
- 🔐 **Encryption** - Packet encryption support (GBCrypto)
- 🌐 **BuddyCenter Integration** - Communication with central server (optional)
- 📦 **Smart Tunneling** - Efficient packet routing between users
- 🎮 **GameServer Integration** - Automatic game status detection

### GUI Features
- 🖥️ **Graphical Interface** - Complete control panel with Tkinter
- 📈 **Live Monitor** - Real-time server metrics visualization
- 📋 **Detailed Logs** - Logging system with colors and timestamps
- ⚙️ **Dynamic Configuration** - Adjust parameters without editing code

## 📦 Requirements

### System
- **Python**: 3.7 or higher
- **MySQL**: 5.7 or higher
- **Operating System**: Windows, Linux or macOS

### Python Dependencies
```
mysql-connector-python
pycryptodome
```

### Database
The server requires a MySQL database with the following tables:
- `User` - User data
- `Game` - Game statistics
- `BuddyList` - Friends list
- `CurrentUser` - Online user status and location
- `LoginLog` - Login records
- `SavePacket` - Offline message storage

## 🚀 Installation

### 1. Clone or download the project
```bash
cd C:\Users\Eletrocel\.gemini\antigravity\playground\tachyon-glenn
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure the database
Run the SQL script to create the necessary tables in your MySQL database:
```sql
-- Make sure the 'gbwc' database exists
CREATE DATABASE IF NOT EXISTS gbwc;
USE gbwc;

-- Tables should follow the original GunBound schema
-- (User, Game, BuddyList, CurrentUser, LoginLog, SavePacket)
```

### 4. Configure the server
Edit the `buddy_server/config.py` file:
```python
class Config:
    # Server Settings
    HOST = '0.0.0.0'      # Server IP
    PORT = 8355           # Buddy Server port
    
    # Database Settings
    DB_HOST = '127.0.0.1'
    DB_USER = 'root'
    DB_PASS = ""
    DB_NAME = "gbwc"
    DB_PORT = 3306
```

## ⚙️ Configuration

### Network Configuration
- **HOST**: `0.0.0.0` - Listen on all network interfaces
- **PORT**: `8355` - Default Buddy Server port (can be changed)

### Database Configuration
Adjust MySQL credentials in `config.py` or through the graphical interface.

### P2P Configuration
The P2P system is automatic and requires no additional configuration. The server:
1. Attempts to establish P2P connection between clients
2. If it fails, uses relay mode (server as intermediary)
3. Monitors success rate and adjusts automatically

## 🎮 Usage

### Start Server (GUI)
```bash
python main.py
```

The graphical interface will open with:
- **Configuration Panel**: Adjust IP, port and database credentials
- **Controls**: Buttons to start/stop server and view statistics
- **Live Monitor**: Real-time status (connections, users, P2P)
- **Logs**: Packet and server event visualization

### Start Server (CLI)
For headless server usage:
```python
from buddy_server.server import BuddyServer
import asyncio

async def main():
    server = BuddyServer(host='0.0.0.0', port=8355)
    await server.start()

if __name__ == "__main__":
    asyncio.run(main())
```

### GUI Commands
- **🚀 START SERVER (P2P)**: Starts the server with P2P support
- **🛑 STOP SERVER**: Stops the server gracefully
- **📊 SHOW STATS**: Displays detailed statistics in popup
- **🗑️ Clear Logs**: Clears the log area

## 🏗️ Architecture

### Main Components

```
┌─────────────────────────────────────────────────────┐
│                   Main.py (GUI)                     │
│              Tkinter Graphical Interface            │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│              BuddyServer (server.py)                │
│            Main Server Manager                      │
├─────────────────────────────────────────────────────┤
│  • ClientConnection - Manages individual connections│
│  • PacketTracer - Packet tracking                  │
│  • User and session registry                       │
└─────┬───────┬───────┬───────┬───────┬──────────────┘
      │       │       │       │       │
      ▼       ▼       ▼       ▼       ▼
┌─────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐
│Database │ │P2P   │ │Invite│ │Status│ │Tunneling │
│Manager  │ │Mgr   │ │Mgr   │ │Mgr   │ │Manager   │
└─────────┘ └──────┘ └──────┘ └──────┘ └──────────┘
```

### Modules

#### `server.py`
- **BuddyServer**: Main server class
- **ClientConnection**: Manages each client connection
- **PacketTracer**: Packet logging system

#### `handlers.py`
Processes all packet types:
- Login and authentication
- Friend management (add/remove)
- Chat and messages
- Game invites
- Status updates
- P2P handshake

#### `database.py`
MySQL interface:
- CRUD operations for users and friends
- Offline message storage
- Status and location queries
- Activity logging

#### `p2p_manager.py`
Hybrid P2P system:
- P2P connection negotiation
- Relay fallback
- Success statistics
- Timeout management

#### `packets.py`
Packet structures:
- **Packet**: Base packet class
- **PacketBuilder**: Packet construction
- **PacketReader**: Packet reading

#### `crypto.py` / `dynamic_crypto.py`
GunBound-compatible packet encryption

#### `user_status.py`
User state management:
- Online, Offline, Busy, Away, Playing, etc.

#### `invites.py`
Game invite system

#### `tunneling.py`
Packet routing between users

## 📡 Communication Protocol

### Packet Structure
```
┌──────────┬──────────┬─────────────────┐
│ Length   │ Opcode   │    Payload      │
│ (2 bytes)│ (2 bytes)│   (N bytes)     │
└──────────┴──────────┴─────────────────┘
```

### Main Opcodes

#### Authentication
- `0x1000` - `SVC_LOGIN_REQ` - Login request
- `0x1001` - `SVC_LOGIN_RESP` - Login response
- `0x1010` - `SVC_LOGIN_DATA` - Login data

#### Friend Management
- `0x3000` - `SVC_ADD_BUDDY` - Add friend
- `0x3001` - `SVC_ADD_BUDDY_RESP` - Response
- `0x3002` - `SVC_REMOVE_BUDDY` - Remove friend
- `0x3003` - `SVC_REMOVE_BUDDY_RESP` - Response
- `0x3004` - `SVC_GROUP_BUDDY` - Move to group
- `0x3006` - `SVC_RENAME_GROUP` - Rename group

#### Status and Synchronization
- `0x3010` - `SVC_USER_STATE` - Status update
- `0x3FFF` - `SVC_USER_SYNC` - User synchronization

#### Messages
- `0x2000` - `SVC_SAVE_PACKET` - Save offline message
- `0x2011` - `SVC_DELETE_PACKET` - Delete message
- `0x2020` - `SVC_TUNNEL_PACKET` - Packet tunneling

#### Search
- `0x4000` - `SVC_SEARCH` - Search user
- `0x4001` - `SVC_SEARCH_RESP` - Search result

## 📁 Project Structure

```
buddy_server/
├── __init__.py              # Module initialization
├── server.py                # Main server
├── config.py                # Configuration
├── constants.py             # Constants (opcodes)
├── packets.py               # Packet structures
├── handlers.py              # Packet handlers
├── database.py              # MySQL interface
├── crypto.py                # Basic encryption
├── dynamic_crypto.py        # Advanced encryption
├── p2p_manager.py           # P2P system
├── user_status.py           # Status management
├── invites.py               # Invite system
├── tunneling.py             # Packet routing
├── center_client.py         # BuddyCenter client
├── hybrid_messaging.py      # Hybrid messaging system
│
├── analyze_bin.py           # Analysis tools
├── check_offline.py         # Offline message checker
├── check_users.py           # User checker
├── debug_db.py              # Database debugger
├── sniffer.py               # Packet sniffer
├── test_*.py                # Various tests
│
└── 3 - SERVIDOR/            # Original GunBound executables
    ├── BuddyCenter2.exe
    ├── BuddyServ2.exe
    ├── GunBoundBroker3.exe
    └── Gunboundserv3.exe
```

## 🛠️ Development

### Debug Tools

#### Packet Sniffer
```bash
python -m buddy_server.sniffer
```
Captures and analyzes packets between client and server.

#### Check Offline Messages
```bash
python -m buddy_server.check_offline
```

#### Database Debugger
```bash
python -m buddy_server.debug_db
```

#### Binary Analysis
```bash
python -m buddy_server.analyze_bin
```

### Adding New Handlers

1. Define the opcode in `constants.py`:
```python
SVC_NEW_FEATURE = 0x5000
```

2. Create the handler in `handlers.py`:
```python
def handle_new_feature(client, reader):
    # Process packet
    data = reader.read_string()
    
    # Respond
    response = PacketBuilder(SVC_NEW_FEATURE_RESP)
    response.write_string("OK")
    client.send_packet(response.build())
```

3. Register in dispatcher in `handle_packet()`:
```python
elif packet_id == SVC_NEW_FEATURE:
    handle_new_feature(client, reader)
```

### Testing

Run unit tests:
```bash
python -m buddy_server.test_p2p_full
python -m buddy_server.test_save
```

## 📊 Monitoring and Statistics

The server provides detailed statistics:

### Server Metrics
- Online users
- Total active connections
- Database state
- BuddyCenter link

### P2P Metrics
- P2P attempts
- Successful connections
- Success rate (%)
- Active P2P connections
- Relay mode connections

### Message Metrics
- Total tunneled messages
- Successful messages
- Offline saved messages
- Delivery rate

### Invite Metrics
- Invites sent
- Invites accepted/rejected
- Active invites

## 🔒 Security

- ✅ Input validation in all handlers
- ✅ SQL injection protection (prepared statements)
- ✅ Packet encryption (optional)
- ✅ Inactive connection timeout
- ✅ Rate limiting - in development

## 🐛 Troubleshooting

### Server won't start
- Check if port 8355 is available
- Verify MySQL credentials
- Check logs for connection errors

### Clients can't connect
- Check firewall and open ports
- Verify IP is correct in client
- Check if database is accessible

### P2P not working
- P2P may fail due to NAT/firewall
- Server automatically uses relay as fallback
- Check logs for P2P failure details

### Offline messages not delivering
- Check `SavePacket` table in database
- Run `check_offline.py` for diagnostics
- Verify recipient is online

## 📝 License

This project is for educational and research purposes. GunBound is property of Softnyx.

## 👥 Contributing

Contributions are welcome! Please:
1. Fork the project
2. Create a branch for your feature
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📧 Support

For questions and support, open an issue in the project repository.

---

**Developed with ❤️ for the GunBound community**
