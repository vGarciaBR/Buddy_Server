
import socket
import struct
import binascii
import subprocess
import time
import os
import signal

# Caminhos (Ajuste se necessário)
BASE_DIR = r"C:\Users\Eletrocel\Desktop\GBB\3 - SERVIDOR\BuddyServ"
EXE_PATH = os.path.join(BASE_DIR, "BuddyServ2.exe")
CONF_PATH = os.path.join(BASE_DIR, "Setting.txt")

MOCK_PORT = 8345 # Porta temporária para interceptação

def modify_config(port):
    """Lê o config, salva backup e altera a porta do Center"""
    if not os.path.exists(CONF_PATH):
        print(f"[-] Config file not found: {CONF_PATH}")
        return False

    with open(CONF_PATH, 'r') as f:
        lines = f.readlines()
    
    # Save Backup
    with open(CONF_PATH + ".bak", 'w') as f:
        f.writelines(lines)
        
    new_lines = []
    for line in lines:
        if "CenterPort=" in line:
            new_lines.append(f"CenterPort={port}\n")
        else:
            new_lines.append(line)
            
    with open(CONF_PATH, 'w') as f:
        f.writelines(new_lines)
    
    print("[*] Config modified temporarily.")
    return True

def restore_config():
    """Restaura o backup"""
    bak_path = CONF_PATH + ".bak"
    if os.path.exists(bak_path):
        with open(bak_path, 'r') as f:
            content = f.read()
        with open(CONF_PATH, 'w') as f:
            f.write(content)
        print("[*] Config restored.")
    else:
        print("[-] Backup not found to restore.")

def run_sniffer():
    print("--- AUTOMATED PACKET SNIFFER ---")
    
    # 1. Setup Config
    if not modify_config(MOCK_PORT):
        return

    # 2. Start Fake Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', MOCK_PORT))
    server.listen(1)
    server.settimeout(10) # 10s timeout
    print(f"[*] Sniffer listening on 127.0.0.1:{MOCK_PORT}")

    # 3. Launch Process
    print(f"[*] Launching {EXE_PATH} -debug...")
    try:
        process = subprocess.Popen([EXE_PATH, "-debug"], cwd=BASE_DIR)
    except Exception as e:
        print(f"[-] Failed to launch exe: {e}")
        restore_config()
        return

    # 4. Wait for connection
    try:
        print("[*] Waiting for connection...")
        client_sock, addr = server.accept()
        print(f"[+] Connection captured from {addr}!")
        
        # PROVOKE CLIENT: Send a dummy header (Len=4, ID=0) or just zeros
        # This acts as a shakehand trigger packet
        print("[*] Sending trigger packet...")
        client_sock.send(b'\x04\x00\x00\x00') 
        
        # 5. Capture Data
        data = client_sock.recv(1024)
        if data:
            print("\n" + "="*40)
            print("CAPTURED PACKET (Hex):")
            print(binascii.hexlify(data).decode('utf-8').upper())
            print("="*40)
            
            # Basic Parse
            try:
                if len(data) >= 4:
                    length, pid = struct.unpack('<HH', data[:4])
                    print(f"Analyzed Header -> Length: {length}, ID: 0x{pid:04X} ({pid})")
                    print(f"Payload Raw: {data[4:]}")
            except:
                print("Could not parse header")
                
            print("="*40 + "\n")
        else:
            print("[-] Connected but no data received.")
            
        client_sock.close()

    except socket.timeout:
        print("[-] Timeout waiting for connection.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        # Cleanup
        print("[*] Killing process...")
        process.terminate()
        try:
            process.wait(timeout=2)
        except:
            process.kill()
            
        server.close()
        restore_config()
        print("[*] Done.")

if __name__ == "__main__":
    run_sniffer()
