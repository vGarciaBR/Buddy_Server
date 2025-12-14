
import socket
import struct
import binascii

def run_mock_center():
    HOST = '127.0.0.1'
    PORT = 8340 # Fake Center Port

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    
    print(f"[*] Mock Center Listening on {HOST}:{PORT}")
    print("[*] Please configure BuddyServ2.exe to connect to this port in Setting.txt")

    while True:
        client_sock, address = server.accept()
        print(f"[*] Connection accepted from {address}")
        
        try:
            # Read Header
            header = client_sock.recv(4)
            if not header or len(header) < 4:
                print("[-] No data or invalid header")
                break
                
            length = struct.unpack('<H', header[:2])[0]
            packet_id = struct.unpack('<H', header[2:])[0]
            
            print(f"[+] HEADER RECV: ID=0x{packet_id:04X} ({packet_id}), Len={length}")
            
            # Read Payload
            payload_len = length - 4
            if payload_len > 0:
                payload = client_sock.recv(payload_len)
                print(f"[+] PAYLOAD HEX: {binascii.hexlify(payload).decode('utf-8').upper()}")
                try:
                    print(f"[+] PAYLOAD ASCII: {payload.decode('latin-1', errors='ignore')}")
                except:
                    pass
            else:
                print("[+] No Payload")
                
            # Keep alive for a bit to see if it sends more
            client_sock.send(b'\x00\x00\x00\x00') # Garbage response to keep connection open?
            
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            client_sock.close()
            print("[*] Connection closed. Restart script if needed.")
            break

if __name__ == "__main__":
    run_mock_center()
