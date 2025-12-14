
import socket
import binascii

# Escutar na porta do Buddy Server (8352)
# Para capturar tentativas de conexão do Jogo
HOST = '127.0.0.1' # Ou '0.0.0.0' para aceitar externo
PORT = 8352

def run_sniffer_client():
    print(f"--- GAME CLIENT SNIFFER (Port {PORT}) ---")
    print("[*] Please STOP the Python Server main.py first!")
    print("[*] Listening for GAME CLIENTS...")
    
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(5)
    except Exception as e:
        print(f"[-] Failed to bind port {PORT}: {e}")
        print("[-] Make sure main.py is STOPPED.")
        return

    while True:
        try:
            print("[*] Waiting for connection...")
            client_sock, addr = server.accept()
            print(f"[+] ⚡ CONNECTION RECEIVED FROM {addr} ⚡")
            print("[*] Waiting for first packet bytes...")
            
            # Read whatever comes
            data = client_sock.recv(1024)
            if data:
                print("\n" + "="*40)
                print("CAPTURED GAME PACKET (Hex):")
                print(binascii.hexlify(data).decode('utf-8').upper())
                print("="*40 + "\n")
            else:
                print("[-] Connected (TCP Handshake OK) but NO DATA sent.")
                
            client_sock.close()
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    run_sniffer_client()
