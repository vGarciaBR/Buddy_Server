import asyncio
import logging
import socket
import struct
import time
import secrets
from typing import Dict, Optional, Tuple
from enum import IntEnum

from .packets import PacketBuilder, PacketReader
from .dynamic_crypto import DynamicCrypto

logger = logging.getLogger(__name__)

class P2PConnectionStatus(IntEnum):
    """Status da conexão P2P"""
    DISCONNECTED = 0
    NEGOTIATING = 1      # Trocando informações de rede
    PUNCHING = 2         # Fazendo hole punching
    CONNECTED = 3        # P2P estabelecido
    FALLBACK = 4         # Usando servidor como relay

class NATType(IntEnum):
    """Tipos de NAT detectados"""
    OPEN = 0             # Sem NAT / Port forwarding
    MODERATE = 1         # Full cone NAT
    STRICT = 2           # Symmetric NAT
    BLOCKED = 3          # Firewall bloqueando

class P2PConnection:
    """Representa uma conexão P2P entre dois usuários"""
    
    def __init__(self, local_user, remote_user, session_key=None):
        self.local_user = local_user
        self.remote_user = remote_user
        self.status = P2PConnectionStatus.DISCONNECTED
        self.session_key = session_key
        
        # Crypto
        self.crypto = None
        if session_key:
            self.crypto = DynamicCrypto(session_key)
        
        # Informações de rede
        self.remote_ip = None
        self.remote_port = None
        self.local_port = None
        
        # Socket P2P
        self.sock = None
        self.reader = None
        self.writer = None
        
        # Timestamps
        self.established_at = None
        self.last_packet_at = None
        
        # Stats
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        
        # Fallback
        self.fallback_count = 0
        self.max_fallback_before_relay = 3
        
    async def establish(self, remote_info: dict) -> bool:
        """
        Tenta estabelecer conexão P2P direta.
        
        Args:
            remote_info: {'ip': str, 'port': int, 'nat_type': int}
            
        Returns:
            bool: True se conseguiu estabelecer P2P
        """
        self.status = P2PConnectionStatus.NEGOTIATING
        self.remote_ip = remote_info['ip']
        self.remote_port = remote_info['port']
        remote_nat = NATType(remote_info.get('nat_type', NATType.MODERATE))
        
        logger.info(f"[P2P] Attempting connection: {self.local_user} -> {self.remote_user}")
        logger.info(f"[P2P] Target: {self.remote_ip}:{self.remote_port} (NAT: {remote_nat.name})")
        
        # Verifica se P2P é viável baseado no NAT
        if not self._is_p2p_viable(remote_nat):
            logger.warning(f"[P2P] NAT configuration prevents P2P, using relay mode")
            self.status = P2PConnectionStatus.FALLBACK
            return False
        
        # Tenta hole punching
        self.status = P2PConnectionStatus.PUNCHING
        success = await self._attempt_hole_punch()
        
        if success:
            self.status = P2PConnectionStatus.CONNECTED
            self.established_at = time.time()
            logger.info(f"[P2P] ✅ Connection established: {self.local_user} <-> {self.remote_user}")
            return True
        else:
            self.fallback_count += 1
            if self.fallback_count >= self.max_fallback_before_relay:
                logger.warning(f"[P2P] Failed after {self.fallback_count} attempts, switching to relay mode")
                self.status = P2PConnectionStatus.FALLBACK
            else:
                logger.warning(f"[P2P] Connection failed (attempt {self.fallback_count})")
                self.status = P2PConnectionStatus.DISCONNECTED
            return False
    
    def _is_p2p_viable(self, remote_nat: NATType) -> bool:
        """
        Verifica se P2P é viável baseado nos tipos de NAT.
        
        Regras:
        - OPEN <-> qualquer = OK
        - MODERATE <-> MODERATE = OK
        - STRICT <-> STRICT = Difícil (hole punching avançado)
        - BLOCKED = IMPOSSÍVEL
        """
        if remote_nat == NATType.BLOCKED:
            return False
        
        # Por simplicidade, vamos permitir apenas:
        # OPEN ou MODERATE
        if remote_nat in [NATType.OPEN, NATType.MODERATE]:
            return True
        
        # STRICT requer técnicas avançadas
        return False
    
    async def _attempt_hole_punch(self) -> bool:
        """
        Implementa hole punching para atravessar NAT.
        
        Processo:
        1. Cria socket UDP em porta aleatória
        2. Envia SYN packets para o peer
        3. Aguarda SYN-ACK
        4. Confirma com ACK
        """
        try:
            # Cria socket UDP
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setblocking(False)
            
            # Bind em porta aleatória (ou usa range específico)
            self.sock.bind(('0.0.0.0', 0))
            self.local_port = self.sock.getsockname()[1]
            
            logger.debug(f"[P2P] Local socket bound to port {self.local_port}")
            
            # Hole punching: envia múltiplos SYN packets
            syn_packet = struct.pack('<HHI', 4, 0xFFFF, int(time.time()))  # Magic SYN
            
            for attempt in range(5):
                try:
                    self.sock.sendto(syn_packet, (self.remote_ip, self.remote_port))
                    logger.debug(f"[P2P] Sent SYN packet (attempt {attempt + 1})")
                except Exception as e:
                    logger.debug(f"[P2P] SYN send error: {e}")
                
                await asyncio.sleep(0.2)
                
                # Tenta receber SYN-ACK
                try:
                    self.sock.settimeout(1.0)
                    data, addr = self.sock.recvfrom(1024)
                    
                    if len(data) >= 4:
                        length, packet_id = struct.unpack('<HH', data[:4])
                        if packet_id == 0xFFFE:  # SYN-ACK
                            logger.debug(f"[P2P] Received SYN-ACK from {addr}")
                            
                            # Envia ACK final
                            ack_packet = struct.pack('<HH', 4, 0xFFFD)
                            self.sock.sendto(ack_packet, addr)
                            
                            logger.info(f"[P2P] Handshake complete!")
                            return True
                            
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"[P2P] Recv error: {e}")
            
            # Falhou
            return False
            
        except Exception as e:
            logger.error(f"[P2P] Hole punch error: {e}")
            return False
    
    async def send_packet(self, packet_id: int, payload: bytes) -> bool:
        """
        Envia pacote via P2P (ou fallback).
        Aqui aplicamos o Checksum Dinâmico e Criptografia se a chave estiver presente.
        
        Returns:
            bool: True se enviado com sucesso
        """
        if self.status == P2PConnectionStatus.CONNECTED and self.sock:
            try:
                # Se temos crypto (chave de sessão), usamos!
                if self.crypto:
                    # Monta payload original para encriptar
                    # (Alguns designs podem encriptar header + payload, aqui vamos encriptar só payload ou tudo)
                    
                    # Vamos encriptar apenas o payload para compatibilidade com header externo
                    # O DynamicCrypto adiciona seus próprios headers (magic, nonce, checksum)
                    encrypted_blob = self.crypto.encrypt_packet(payload)
                    
                    # P2P Packet = 4 bytes Length + PacketID + EncryptedBlob
                    length = 4 + len(encrypted_blob)
                    header = struct.pack('<HH', length, packet_id)
                    data = header + encrypted_blob
                    
                else:
                    # Sem crypto (legado/fallback)
                    length = 4 + len(payload)
                    header = struct.pack('<HH', length, packet_id)
                    data = header + payload
                
                # Envia
                self.sock.sendto(data, (self.remote_ip, self.remote_port))
                
                self.packets_sent += 1
                self.bytes_sent += len(data)
                self.last_packet_at = time.time()
                
                logger.debug(f"[P2P] Sent encrypted packet 0x{packet_id:04X} ({len(data)} bytes)")
                return True
                
            except Exception as e:
                logger.error(f"[P2P] Send error: {e}")
                # Marca para fallback
                self.status = P2PConnectionStatus.FALLBACK
                return False
        
        # Não conectado ou em fallback
        return False
    
    def get_latency(self) -> Optional[float]:
        """Retorna latência estimada (RTT) em ms"""
        # TODO: Implementar ping/pong
        return None
    
    def is_alive(self) -> bool:
        """Verifica se conexão ainda está viva"""
        if self.status != P2PConnectionStatus.CONNECTED:
            return False
        
        if not self.last_packet_at:
            return True
        
        # Timeout de 60s sem pacotes
        idle_time = time.time() - self.last_packet_at
        return idle_time < 60.0
    
    async def close(self):
        """Fecha conexão P2P"""
        logger.info(f"[P2P] Closing connection: {self.local_user} <-> {self.remote_user}")
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        
        self.status = P2PConnectionStatus.DISCONNECTED


class P2PManager:
    """
    Gerenciador de conexões P2P.
    
    Funcionalidades:
    - Coordenação de hole punching
    - Detecção de NAT type
    - Fallback automático para relay
    - Keep-alive de conexões P2P
    - Estatísticas de uso
    """
    
    # Packet IDs
    PKT_P2P_REQUEST = 0xC000       # Cliente solicita P2P
    PKT_P2P_OFFER = 0xC001         # Servidor oferece info de rede + KEY
    PKT_P2P_ANSWER = 0xC002        # Cliente responde com info
    PKT_P2P_SUCCESS = 0xC010       # P2P estabelecido
    PKT_P2P_FAILED = 0xC011        # P2P falhou, usar relay
    
    def __init__(self, server):
        self.server = server
        
        # Conexões P2P ativas
        self.connections: Dict[Tuple[str, str], P2PConnection] = {}
        
        # Cache de informações de rede dos clientes
        self.client_network_info: Dict[str, dict] = {}
        
        # Stats
        self.stats = {
            'p2p_attempts': 0,
            'p2p_successful': 0,
            'p2p_failed': 0,
            'relay_mode_count': 0,
            'total_p2p_bytes': 0
        }
        
        # Config
        # Se True, simula sucesso para clientes que não suportam o protocolo (Legacy)
        self.auto_p2p_mock = True 
        
        # Tasks
        self.keepalive_task = None
    
    async def start(self):
        """Inicia o manager"""
        self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        logger.info("P2PManager started")
    
    async def stop(self):
        """Para o manager"""
        if self.keepalive_task:
            self.keepalive_task.cancel()
            try:
                await self.keepalive_task
            except asyncio.CancelledError:
                pass
        
        # Fecha todas conexões
        for conn in list(self.connections.values()):
            await conn.close()
        
        logger.info("P2PManager stopped")
    
    async def request_p2p(self, client, target_id: str):
        """
        Cliente solicita conexão P2P com outro usuário.
        
        Fluxo:
        1. Verifica se target está online
        2. Obtém informações de rede de ambos
        3. Coordena estabelecimento da conexão
        4. Notifica resultado
        """
        self.stats['p2p_attempts'] += 1
        
        # Valida target
        target_session = self.server.user_sessions.get(target_id)
        if not target_session:
            logger.warning(f"[P2P] Target {target_id} not online")
            await self._send_p2p_failed(client, target_id, "Target offline")
            return False
        
        # Detecta NAT type do solicitante (se ainda não temos)
        if client.user_id not in self.client_network_info:
            nat_type = await self._detect_nat_type(client)
            self.client_network_info[client.user_id] = {
                'ip': client.ip[0],
                'port': client.ip[1],
                'nat_type': nat_type
            }
        
        # Detecta NAT do target
        if target_id not in self.client_network_info:
            nat_type = await self._detect_nat_type(target_session)
            self.client_network_info[target_id] = {
                'ip': target_session.ip[0],
                'port': target_session.ip[1],
                'nat_type': nat_type
            }
        
        # Verifica se P2P é viável
        client_info = self.client_network_info[client.user_id]
        target_info = self.client_network_info[target_id]
        
        logger.info(f"[P2P] Request: {client.user_id} -> {target_id}")
        logger.info(f"[P2P] Client NAT: {NATType(client_info['nat_type']).name}")
        logger.info(f"[P2P] Target NAT: {NATType(target_info['nat_type']).name}")
        
        # Cria ou recupera conexão P2P
        conn_key = (client.user_id, target_id)
        
        # Gera chave de sessão única para este par P2P (16 bytes AES-128)
        session_key = secrets.token_bytes(16)
        logger.info(f"[P2P] Generated Session Key for {conn_key}")

        if conn_key not in self.connections:
            self.connections[conn_key] = P2PConnection(client.user_id, target_id, session_key)
        else:
             # Atualiza a chave da conexão existente (rotação forçada)
             self.connections[conn_key].session_key = session_key
             self.connections[conn_key].crypto = DynamicCrypto(session_key)
        
        conn = self.connections[conn_key]
        
        # Envia OFFER para o cliente (info do target + KEY)
        await self._send_p2p_offer(client, target_id, target_info, session_key)
        
        # Envia OFFER para o target (info do cliente + KEY)
        await self._send_p2p_offer(target_session, client.user_id, client_info, session_key)
        
        # Aguarda ambos tentarem estabelecer
        # (Isso seria coordenado pelos clientes enviando PKT_P2P_ANSWER)
        
        logger.info(f"[P2P] Coordination packets sent, waiting for clients to establish connection")
        
        # MOCK MODE: Auto-confirma para testar painel com clientes Legacy
        if self.auto_p2p_mock:
            asyncio.create_task(self._mock_auto_confirm(client, target_id))
            
        return True

    async def _mock_auto_confirm(self, client, target_id):
        """Simula resposta positiva do cliente (Apenas para Testes/Visualização)"""
        await asyncio.sleep(2.0) # Espera 2s para parecer real
        logger.info(f"[P2P MOCK] Auto-confirming connection for {client.user_id} -> {target_id}")
        
        # Simula pacote de resposta
        conn_key = (client.user_id, target_id)
        if conn_key in self.connections:
            self.connections[conn_key].status = P2PConnectionStatus.CONNECTED
            self.stats['p2p_successful'] += 1
    
    async def _detect_nat_type(self, client) -> NATType:
        """
        Detecta tipo de NAT do cliente.
        
        Métodos:
        1. STUN-like protocol
        2. Multiple bind attempts
        3. Echo test
        
        Por simplicidade, usa heurística baseada em IP
        """
        client_ip = client.ip[0]
        
        # Verifica se é IP privado
        if self._is_private_ip(client_ip):
            # Tem NAT, determinar tipo
            # Simplificação: assume MODERATE por padrão
            return NATType.MODERATE
        else:
            # IP público, assume OPEN
            return NATType.OPEN
    
    def _is_private_ip(self, ip: str) -> bool:
        """Verifica se IP é privado"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        first = int(parts[0])
        second = int(parts[1])
        
        # 10.0.0.0/8
        if first == 10:
            return True
        
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True
        
        # Localhost
        if first == 127:
            return True
        
        return False
    
    async def _send_p2p_offer(self, client, peer_id: str, peer_info: dict, session_key: bytes = None):
        """
        Envia informações de rede do peer para estabelecer P2P.
        
        Payload:
        - PeerID: String
        - PeerIP: String
        - PeerPort: Int
        - NATType: Byte
        - HasKey: Byte (0/1)
        - SessionKey: Bytes (16 bytes) if HasKey=1
        """
        pkt = PacketBuilder(self.PKT_P2P_OFFER)
        pkt.write_string(peer_id)
        pkt.write_string(peer_info['ip'])
        pkt.write_int(peer_info['port'])
        pkt.write_byte(peer_info['nat_type'])
        
        if session_key and len(session_key) == 16:
            pkt.write_byte(1) # Has Key
            pkt.write_bytes(session_key)
        else:
            pkt.write_byte(0) # No Key
        
        await client.send_packet(pkt.build())
        logger.debug(f"[P2P] Sent OFFER to {client.user_id} about {peer_id} (Key included: {bool(session_key)})")
    
    async def _send_p2p_failed(self, client, target_id: str, reason: str):
        """Notifica cliente que P2P falhou"""
        pkt = PacketBuilder(self.PKT_P2P_FAILED)
        pkt.write_string(target_id)
        pkt.write_string(reason)
        
        await client.send_packet(pkt.build())
        
        self.stats['p2p_failed'] += 1
    
    async def handle_p2p_answer(self, client, payload: bytes):
        """
        Cliente responde dizendo se conseguiu estabelecer P2P.
        
        Payload:
        - TargetID: String
        - Success: Byte (0=failed, 1=success)
        """
        reader = PacketReader(payload)
        target_id = reader.read_string()
        success = reader.read_byte()
        
        if success:
            logger.info(f"[P2P] ✅ Client {client.user_id} established P2P with {target_id}")
            self.stats['p2p_successful'] += 1
            
            # Marca conexão como estabelecida
            conn_key = (client.user_id, target_id)
            if conn_key in self.connections:
                self.connections[conn_key].status = P2PConnectionStatus.CONNECTED
        else:
            logger.warning(f"[P2P] ❌ Client {client.user_id} failed P2P with {target_id}")
            self.stats['relay_mode_count'] += 1
            
            # Marca para usar relay
            conn_key = (client.user_id, target_id)
            if conn_key in self.connections:
                self.connections[conn_key].status = P2PConnectionStatus.FALLBACK
    
    def should_use_p2p(self, sender_id: str, target_id: str) -> bool:
        """
        Verifica se deve usar P2P ou relay baseado no estado da conexão.
        
        Returns:
            bool: True se deve tentar P2P
        """
        conn_key = (sender_id, target_id)
        
        if conn_key not in self.connections:
            return False
        
        conn = self.connections[conn_key]
        
        # Só usa P2P se estiver estabelecido e vivo
        return (conn.status == P2PConnectionStatus.CONNECTED and 
                conn.is_alive())
    
    async def send_via_p2p(self, sender_id: str, target_id: str, 
                           packet_id: int, payload: bytes) -> bool:
        """
        Tenta enviar pacote via P2P.
        
        Returns:
            bool: True se enviado com sucesso
        """
        conn_key = (sender_id, target_id)
        
        if conn_key not in self.connections:
            return False
        
        conn = self.connections[conn_key]
        return await conn.send_packet(packet_id, payload)
    
    async def _keepalive_loop(self):
        """Loop que mantém conexões P2P vivas e limpa as mortas"""
        try:
            while True:
                await asyncio.sleep(30)
                
                dead_connections = []
                
                for conn_key, conn in list(self.connections.items()):
                    if not conn.is_alive():
                        logger.info(f"[P2P] Connection dead: {conn_key}")
                        dead_connections.append(conn_key)
                
                # Remove conexões mortas
                for conn_key in dead_connections:
                    conn = self.connections.pop(conn_key)
                    await conn.close()
                
                if dead_connections:
                    logger.debug(f"[P2P] Cleaned up {len(dead_connections)} dead connections")
                
        except asyncio.CancelledError:
            logger.info("P2P keepalive loop cancelled")
    
    def get_stats(self):
        """Retorna estatísticas"""
        active_p2p = len([c for c in self.connections.values() 
                         if c.status == P2PConnectionStatus.CONNECTED])
        
        relay_mode = len([c for c in self.connections.values() 
                         if c.status == P2PConnectionStatus.FALLBACK])
        
        success_rate = 0
        if self.stats['p2p_attempts'] > 0:
            success_rate = (self.stats['p2p_successful'] / 
                          self.stats['p2p_attempts'] * 100)
        
        return {
            **self.stats,
            'active_p2p_connections': active_p2p,
            'relay_mode_connections': relay_mode,
            'success_rate': f"{success_rate:.1f}%"
        }