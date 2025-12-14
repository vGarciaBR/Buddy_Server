import logging
from .packets import PacketBuilder, PacketReader
from .constants import SVC_TUNNEL_PACKET

logger = logging.getLogger(__name__)

class TunnelingManager:
    """
    Gerenciador avançado de packet tunneling.
    
    Funcionalidades:
    - Encaminhamento robusto de pacotes entre usuários
    - Suporte para múltiplos tipos de payload
    - Validação e sanitização automática
    - Fallback para mensagens offline
    - Retry logic para falhas temporárias
    """
    
    # Tipos de pacotes que podem ser tunelados
    TUNELABLE_PACKETS = {
        0xA110: 'CHAT',           # Mensagem de chat
        0xA200: 'BUDDY_ACTION',   # Ação de amigo
        0x1030: 'NOTE',           # Nota/recado
        0xA300: 'GAME_INVITE',    # Convite de jogo
        0xA400: 'FILE_TRANSFER',  # Transferência de arquivo
        0xA510: 'STATUS_UPDATE',  # Atualização de status
    }
    
    def __init__(self, server):
        self.server = server
        self.tunnel_stats = {
            'total_tunneled': 0,
            'successful': 0,
            'failed': 0,
            'offline_saved': 0,
            'retries': 0
        }
        
    async def tunnel_packet(self, sender_client, target_id, packet_id, payload, 
                           retry_count=0, max_retries=2):
        """
        Tunela um pacote de sender para target com retry logic.
        
        Args:
            sender_client: Cliente que enviou
            target_id: ID do destinatário
            packet_id: ID do pacote original
            payload: Dados do pacote
            retry_count: Tentativas atuais
            max_retries: Máximo de tentativas
            
        Returns:
            bool: True se enviado com sucesso ou salvo offline
        """
        self.tunnel_stats['total_tunneled'] += 1
        
        # Validação de segurança
        if not self._validate_tunnel_request(sender_client, target_id, packet_id):
            logger.warning(f"Tunnel validation failed: {sender_client.user_id} -> {target_id}")
            self.tunnel_stats['failed'] += 1
            return False
        
        # Sanitiza payload
        sanitized_payload = self._sanitize_payload(packet_id, payload)
        
        # Tenta enviar para usuário online
        target_session = self.server.user_sessions.get(target_id)
        
        if target_session:
            try:
                # Testa se a conexão está realmente viva
                if not await self._is_connection_alive(target_session):
                    logger.warning(f"Target {target_id} connection is dead (zombie)")
                    raise ConnectionError("Zombie connection detected")
                
                # Constrói pacote tunelado
                tunnel_packet = self._build_tunnel_packet(
                    sender_client.user_id, 
                    packet_id, 
                    sanitized_payload
                )
                
                await target_session.send_packet(tunnel_packet)
                
                self.tunnel_stats['successful'] += 1
                logger.info(f"[TUNNEL] {sender_client.user_id} -> {target_id} (0x{packet_id:04X}) ✓")
                
                return True
                
            except Exception as e:
                logger.warning(f"Tunnel send failed: {e}")
                
                # Remove sessão zumbi
                if target_id in self.server.user_sessions:
                    del self.server.user_sessions[target_id]
                    logger.info(f"Removed zombie session: {target_id}")
                
                # Retry logic
                if retry_count < max_retries:
                    self.tunnel_stats['retries'] += 1
                    logger.info(f"Retrying tunnel (attempt {retry_count + 1}/{max_retries})...")
                    import asyncio
                    await asyncio.sleep(0.5)
                    return await self.tunnel_packet(
                        sender_client, target_id, packet_id, 
                        payload, retry_count + 1, max_retries
                    )
        
        # Usuário offline ou todas tentativas falharam - salva no banco
        return await self._save_offline_tunnel(
            sender_client.user_id, 
            target_id, 
            packet_id, 
            sanitized_payload
        )
    
    def _validate_tunnel_request(self, sender_client, target_id, packet_id):
        """
        Valida se o tunelamento é permitido.
        """
        # Verificar autenticação
        if not sender_client.is_authenticated:
            logger.warning(f"Unauthenticated tunnel attempt from {sender_client.ip}")
            return False
        
        # Verificar se sender não está tentando enviar para si mesmo
        if sender_client.user_id == target_id:
            logger.debug(f"Self-tunnel blocked: {sender_client.user_id}")
            return False
        
        # Verificar se o packet type é tunelável
        if packet_id not in self.TUNELABLE_PACKETS:
            logger.warning(f"Non-tunelable packet type: 0x{packet_id:04X}")
            return False
        
        # Verificar se target existe
        target_exists = self.server.db.get_userno(target_id)
        if not target_exists:
            logger.warning(f"Target user does not exist: {target_id}")
            return False
        
        return True
    
    def _sanitize_payload(self, packet_id, payload):
        """Sanitiza payload baseado no tipo de pacote."""
        MAX_PAYLOAD_SIZE = 4096
        
        if len(payload) > MAX_PAYLOAD_SIZE:
            logger.warning(f"Payload too large ({len(payload)} bytes), truncating")
            payload = payload[:MAX_PAYLOAD_SIZE]
        
        if packet_id == 0xA110:  # Chat
            return self._sanitize_chat_payload(payload)
        
        return payload
    
    def _sanitize_chat_payload(self, payload):
        """Sanitiza payload de chat."""
        try:
            if b'\x00' not in payload:
                return payload
            
            parts = payload.split(b'\x00', 1)
            if len(parts) < 2 or len(parts[1]) < 9:
                return payload
            
            clean_buf = bytearray()
            clean_buf.extend(parts[0])
            clean_buf.append(0)
            clean_buf.extend(b'\x00' * 9)
            clean_buf.extend(parts[1][9:])
            
            return bytes(clean_buf)
            
        except Exception as e:
            logger.error(f"Chat sanitization error: {e}")
            return payload
    
    def _build_tunnel_packet(self, sender_id, original_packet_id, payload):
        """Constrói pacote tunelado para envio."""
        tunnel_pkt = PacketBuilder(original_packet_id)
        tunnel_pkt.buffer = bytearray(payload)
        return tunnel_pkt.build()
    
    async def _is_connection_alive(self, client_session):
        """Testa se a conexão do cliente está realmente viva."""
        try:
            if client_session.writer.is_closing():
                return False
            return True
        except Exception as e:
            logger.debug(f"Connection check failed: {e}")
            return False
    
    async def _save_offline_tunnel(self, sender_id, target_id, packet_id, payload):
        """Salva pacote tunelado como mensagem offline."""
        try:
            body_hex = payload.hex()
            
            success = self.server.db.save_packet(
                sender_id, 
                target_id, 
                packet_id, 
                body_hex
            )
            
            if success:
                self.tunnel_stats['offline_saved'] += 1
                logger.info(f"[TUNNEL OFFLINE] {sender_id} -> {target_id} saved to DB")
                return True
            else:
                self.tunnel_stats['failed'] += 1
                logger.error(f"Failed to save offline tunnel to DB")
                return False
                
        except Exception as e:
            logger.error(f"Error saving offline tunnel: {e}")
            self.tunnel_stats['failed'] += 1
            return False
    
    async def deliver_offline_tunnels(self, client):
        """Entrega pacotes tunelados salvos quando usuário loga."""
        user_id = client.user_id
        offline_packets = self.server.db.get_packets(user_id)
        
        if not offline_packets:
            return
        
        logger.info(f"[TUNNEL DELIVERY] Delivering {len(offline_packets)} offline packets to {user_id}")
        
        import asyncio
        await asyncio.sleep(1.0)
        
        sender_cache = set()
        
        for pkt_data in offline_packets:
            try:
                sender = pkt_data.get('Sender', 'Unknown')
                packet_id = pkt_data.get('Code', 0xA110)
                body_hex = pkt_data['Body']
                
                if sender != 'Unknown' and sender not in sender_cache:
                    await self._send_fake_online(client, sender)
                    sender_cache.add(sender)
                    await asyncio.sleep(0.3)
                
                try:
                    payload = bytes.fromhex(body_hex)
                except ValueError:
                    payload = body_hex.encode('latin1')
                
                payload = self._sanitize_payload(packet_id, payload)
                
                out_pkt = PacketBuilder(packet_id)
                out_pkt.buffer = bytearray(payload)
                await client.send_packet(out_pkt.build())
                
                self.server.db.delete_packet(pkt_data['SerialNo'])
                
                logger.debug(f"Delivered offline tunnel from {sender} (0x{packet_id:04X})")
                
                await asyncio.sleep(0.2)
                
            except Exception as e:
                logger.error(f"Error delivering offline tunnel: {e}")
                continue
        
        logger.info(f"[TUNNEL DELIVERY] Completed for {user_id}")
    
    async def _send_fake_online(self, client, user_id):
        """Envia notificação fake de online."""
        try:
            nick = user_id
            info = self.server.db.get_users_info([user_id])
            if info:
                nick = info[0].get('Nickname', user_id)
            
            fake_list = PacketBuilder(0x1010)
            fake_list.write_byte(1)
            fake_list.write_string(nick)
            fake_list.write_byte(1)
            fake_list.write_string(user_id)
            fake_list.write_int(0)
            
            await client.send_packet(fake_list.build())
            logger.debug(f"Sent fake online notification: {user_id}")
            
        except Exception as e:
            logger.error(f"Error sending fake online: {e}")
    
    def get_stats(self):
        """Retorna estatísticas de tunneling"""
        success_rate = 0
        if self.tunnel_stats['total_tunneled'] > 0:
            success_rate = (self.tunnel_stats['successful'] / 
                          self.tunnel_stats['total_tunneled'] * 100)
        
        return {
            **self.tunnel_stats,
            'success_rate': f"{success_rate:.1f}%"
        }
    
    def reset_stats(self):
        """Reseta estatísticas"""
        self.tunnel_stats = {
            'total_tunneled': 0,
            'successful': 0,
            'failed': 0,
            'offline_saved': 0,
            'retries': 0
        }