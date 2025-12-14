import asyncio
import logging
from .packets import PacketBuilder, Packet

logger = logging.getLogger(__name__)

class BuddyCenterClient:
    """
    Cliente completo para BuddyCenter (porta 8339).
    
    Funcionalidades:
    - Registro automático do BuddyServ no Center
    - Heartbeat periódico
    - Sincronização de estado de usuários
    - Notificações cross-server
    - Reconexão automática
    """
    
    # Packet IDs do Center Protocol
    CTR_REG_LOGIN = 0x2001          # Registro do servidor
    CTR_REG_LOGIN_RESP = 0x2002     # Resposta de registro
    CTR_HEARTBEAT = 0x2010          # Keep-alive
    CTR_HEARTBEAT_RESP = 0x2011     # Resposta heartbeat
    CTR_USER_LOGIN = 0x3010         # Notificar login de usuário
    CTR_USER_LOGOUT = 0x3011        # Notificar logout de usuário
    CTR_USER_STATE = 0x3012         # Mudança de estado
    SVC_USER_STATE = 0x2030         # Broadcast de estado (recebido)
    SVC_USER_SYNC = 0x3FFF          # Sync completo de usuários
    
    def __init__(self, center_ip, center_port, server_name="BuddyServ", server_port=8352):
        self.center_ip = center_ip
        self.center_port = center_port
        self.server_name = server_name
        self.server_port = server_port
        
        self.reader = None
        self.writer = None
        self.connected = False
        self.registered = False
        
        # Heartbeat config
        self.heartbeat_interval = 30  # segundos
        self.heartbeat_task = None
        self.receive_task = None
        self.reconnect_task = None
        
        # Stats
        self.last_heartbeat = None
        self.messages_sent = 0
        self.messages_received = 0
        
        # Referência ao servidor principal
        self.buddy_server = None
        
    def set_server(self, server):
        """Injeta referência ao BuddyServer principal"""
        self.buddy_server = server
        
    async def connect(self):
        """Conecta ao BuddyCenter com retry automático"""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Connecting to BuddyCenter at {self.center_ip}:{self.center_port} (Attempt {attempt + 1}/{max_retries})...")
                
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(self.center_ip, self.center_port),
                    timeout=10.0
                )
                
                self.connected = True
                logger.info("✓ Connected to BuddyCenter successfully!")
                
                # Inicia tasks
                self.receive_task = asyncio.create_task(self._receive_loop())
                
                # Envia registro
                await self._send_registration()
                
                # Aguarda confirmação de registro (com timeout)
                await asyncio.sleep(2.0)
                
                if self.registered:
                    # Inicia heartbeat apenas se registrado
                    self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
                    logger.info("✓ BuddyCenter integration fully initialized")
                    return True
                else:
                    logger.warning("Registration not confirmed, but connection established")
                    return True
                    
            except asyncio.TimeoutError:
                logger.error(f"Connection timeout to BuddyCenter (Attempt {attempt + 1})")
            except ConnectionRefusedError:
                logger.error(f"BuddyCenter refused connection (Attempt {attempt + 1})")
            except Exception as e:
                logger.error(f"Failed to connect to BuddyCenter: {e} (Attempt {attempt + 1})")
            
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
        
        logger.warning("Could not connect to BuddyCenter after all retries. Running in standalone mode.")
        self.connected = False
        
        # Inicia task de reconexão em background
        self.reconnect_task = asyncio.create_task(self._reconnect_loop())
        return False
        
    async def _reconnect_loop(self):
        """Loop de reconexão automática em background"""
        while not self.connected:
            try:
                await asyncio.sleep(60)  # Tenta reconectar a cada 60s
                logger.info("Attempting automatic reconnection to BuddyCenter...")
                success = await self.connect()
                if success:
                    logger.info("✓ Reconnected to BuddyCenter successfully!")
                    break
            except Exception as e:
                logger.debug(f"Reconnection attempt failed: {e}")
        
    async def _send_registration(self):
        """
        Envia pacote de registro ao Center.
        
        Estrutura (baseada em análise):
        - Version: Int (1)
        - ServerPort: Int
        - ServerName: String
        - MaxUsers: Int (opcional)
        """
        reg_packet = PacketBuilder(self.CTR_REG_LOGIN)
        reg_packet.write_int(1)                    # Protocol Version
        reg_packet.write_int(self.server_port)     # Nossa porta
        reg_packet.write_string(self.server_name)  # Nome do servidor
        reg_packet.write_int(1000)                 # Max users (capacidade)
        
        await self._send_packet(reg_packet.build())
        logger.info(f"Sent registration packet to BuddyCenter (Port: {self.server_port}, Name: {self.server_name})")
        
    async def _heartbeat_loop(self):
        """Loop de heartbeat periódico"""
        try:
            while self.connected and self.registered:
                await asyncio.sleep(self.heartbeat_interval)
                
                hb_packet = PacketBuilder(self.CTR_HEARTBEAT)
                hb_packet.write_int(len(self.buddy_server.user_sessions) if self.buddy_server else 0)
                hb_packet.write_int(int(asyncio.get_event_loop().time()))
                
                await self._send_packet(hb_packet.build())
                self.last_heartbeat = asyncio.get_event_loop().time()
                
                logger.debug(f"Heartbeat sent to BuddyCenter (Users: {len(self.buddy_server.user_sessions) if self.buddy_server else 0})")
                
        except asyncio.CancelledError:
            logger.info("Heartbeat loop cancelled")
        except Exception as e:
            logger.error(f"Error in heartbeat loop: {e}")
            self.connected = False
            
    async def _send_packet(self, packet):
        """Envia pacote ao Center com validação"""
        if not self.writer or not self.connected:
            logger.warning("Cannot send packet - not connected to Center")
            return False
            
        try:
            data = packet.to_bytes()
            self.writer.write(data)
            await self.writer.drain()
            self.messages_sent += 1
            return True
        except Exception as e:
            logger.error(f"Error sending packet to Center: {e}")
            self.connected = False
            return False
            
    async def _receive_loop(self):
        """Loop para receber mensagens do Center"""
        try:
            while self.connected:
                # Lê header (4 bytes)
                header = await self.reader.readexactly(4)
                packet_len = int.from_bytes(header[:2], 'little')
                packet_id = int.from_bytes(header[2:], 'little')
                
                # Lê payload
                payload_len = packet_len - 4
                if payload_len > 0:
                    payload = await self.reader.readexactly(payload_len)
                else:
                    payload = b''
                
                self.messages_received += 1
                logger.debug(f"[CENTER] Received packet 0x{packet_id:04X}")
                
                await self._handle_center_packet(packet_id, payload)
                
        except asyncio.IncompleteReadError:
            logger.warning("BuddyCenter connection closed")
            self.connected = False
            self.registered = False
        except Exception as e:
            logger.error(f"Error in Center receive loop: {e}")
            self.connected = False
            self.registered = False
        finally:
            # Tenta reconectar
            if not self.connected:
                logger.info("Starting reconnection attempts...")
                self.reconnect_task = asyncio.create_task(self._reconnect_loop())
            
    async def _handle_center_packet(self, packet_id, payload):
        """Processa pacotes recebidos do Center"""
        
        if packet_id == self.CTR_REG_LOGIN_RESP:
            # Resposta de registro
            if len(payload) >= 4:
                result = int.from_bytes(payload[:4], 'little')
                if result == 1:
                    self.registered = True
                    logger.info("✓ Registration confirmed by BuddyCenter")
                else:
                    logger.error(f"Registration failed with code: {result}")
                    
        elif packet_id == self.CTR_HEARTBEAT_RESP:
            # Resposta de heartbeat
            logger.debug("Heartbeat acknowledged by Center")
            
        elif packet_id == self.SVC_USER_STATE:
            # Atualização de estado de usuário de outro servidor
            await self._handle_user_state_update(payload)
            
        elif packet_id == self.SVC_USER_SYNC:
            # Sincronização completa de usuários
            await self._handle_user_sync(payload)
            
        else:
            logger.debug(f"Unhandled Center packet: 0x{packet_id:04X}")
            
    async def _handle_user_state_update(self, payload):
        """
        Processa atualização de estado de usuário vinda de outro servidor.
        
        Estrutura:
        - UserID: String
        - State: Byte (0=Offline, 1=Online, 2=Busy, 3=InGame)
        - ServerIP: String (opcional)
        - ServerPort: Int (opcional)
        """
        if not self.buddy_server:
            return
            
        try:
            from .packets import PacketReader
            reader = PacketReader(payload)
            
            user_id = reader.read_string()
            state = reader.read_byte()
            
            logger.info(f"[CENTER SYNC] User {user_id} is now state={state}")
            
            # Propaga para os amigos deste usuário que estão conectados AQUI
            if user_id not in self.buddy_server.user_sessions:
                # Usuário não está neste servidor, mas pode ter amigos aqui
                # Busca amigos no banco
                friends = self.buddy_server.db.get_buddy_list(user_id)
                
                for friend_data in friends:
                    friend_id = friend_data.get('friend_id')
                    friend_session = self.buddy_server.user_sessions.get(friend_id)
                    
                    if friend_session:
                        # Envia notificação de mudança de estado
                        notif = PacketBuilder(0x3010)  # SVC_USER_STATE
                        notif.write_string(user_id)
                        notif.write_byte(state)
                        await friend_session.send_packet(notif.build())
                        
                        logger.debug(f"Propagated state update to friend {friend_id}")
                        
        except Exception as e:
            logger.error(f"Error handling user state update: {e}")
            
    async def _handle_user_sync(self, payload):
        """Processa sincronização completa de usuários online"""
        logger.info("[CENTER SYNC] Received full user sync")
        # TODO: Implementar parse de lista completa se necessário
        
    async def notify_user_login(self, user_id, state=1):
        """
        Notifica o Center que um usuário logou no BuddyServ.
        
        Args:
            user_id: ID do usuário
            state: Estado (1=Online, 2=Busy, 3=InGame)
        """
        if not self.connected or not self.registered:
            logger.debug(f"Cannot notify Center of login - not connected/registered")
            return
            
        packet = PacketBuilder(self.CTR_USER_LOGIN)
        packet.write_string(user_id)
        packet.write_byte(state)
        packet.write_int(self.server_port)  # Qual servidor
        
        success = await self._send_packet(packet.build())
        if success:
            logger.info(f"[CENTER] Notified login: {user_id} (state={state})")
        
    async def notify_user_logout(self, user_id):
        """Notifica o Center que um usuário deslogou"""
        if not self.connected or not self.registered:
            return
            
        packet = PacketBuilder(self.CTR_USER_LOGOUT)
        packet.write_string(user_id)
        
        success = await self._send_packet(packet.build())
        if success:
            logger.info(f"[CENTER] Notified logout: {user_id}")
            
    async def notify_user_state_change(self, user_id, new_state):
        """
        Notifica mudança de estado de usuário.
        
        States:
        0 = Offline
        1 = Online/Lobby
        2 = Busy
        3 = In Game
        """
        if not self.connected or not self.registered:
            return
            
        packet = PacketBuilder(self.CTR_USER_STATE)
        packet.write_string(user_id)
        packet.write_byte(new_state)
        
        success = await self._send_packet(packet.build())
        if success:
            logger.debug(f"[CENTER] Notified state change: {user_id} -> {new_state}")
        
    async def disconnect(self):
        """Desconecta do Center gracefully"""
        logger.info("Disconnecting from BuddyCenter...")
        
        # Cancela tasks
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
                
        if self.receive_task:
            self.receive_task.cancel()
            try:
                await self.receive_task
            except asyncio.CancelledError:
                pass
        
        self.connected = False
        self.registered = False
        
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except:
                pass
                
        logger.info("✓ Disconnected from BuddyCenter")
        
    def get_stats(self):
        """Retorna estatísticas da conexão"""
        return {
            'connected': self.connected,
            'registered': self.registered,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
            'last_heartbeat': self.last_heartbeat,
            'uptime': asyncio.get_event_loop().time() - (self.last_heartbeat or 0) if self.last_heartbeat else 0
        }