import asyncio
import logging
import time
import uuid
from enum import IntEnum
from typing import Dict, Optional

from .packets import PacketBuilder

logger = logging.getLogger(__name__)

class InviteType(IntEnum):
    """Tipos de convite"""
    BUDDY = 1       # Convite de amizade
    GAME = 2        # Convite para jogo
    GUILD = 3       # Convite para guilda
    PARTY = 4       # Convite para grupo

class InviteStatus(IntEnum):
    """Status de um convite"""
    PENDING = 0
    ACCEPTED = 1
    REJECTED = 2
    CANCELLED = 3
    EXPIRED = 4

class Invite:
    """Representa um convite"""
    def __init__(self, invite_id, sender_id, target_id, invite_type, data=None, expiry_seconds=120):
        self.invite_id = invite_id
        self.sender_id = sender_id
        self.target_id = target_id
        self.invite_type = invite_type
        self.data = data or {}
        self.status = InviteStatus.PENDING
        self.created_at = time.time()
        self.expires_at = self.created_at + expiry_seconds
        
    def is_expired(self):
        """Verifica se o convite expirou"""
        return time.time() > self.expires_at
    
    def time_remaining(self):
        """Retorna tempo restante em segundos"""
        return max(0, self.expires_at - time.time())

class InviteManager:
    """
    Gerenciador de sistema de convites.
    
    Funcionalidades:
    - Convites de amizade
    - Convites para jogos
    - Convites para guildas
    - Expiração automática
    - Notificações em tempo real
    """
    
    # Packet IDs
    PKT_INVITE_SEND = 0xA300
    PKT_INVITE_RECEIVE = 0xA301
    PKT_INVITE_ACCEPT = 0xA302
    PKT_INVITE_REJECT = 0xA303
    PKT_INVITE_CANCEL = 0xA304
    PKT_INVITE_EXPIRED = 0xA305
    
    def __init__(self, server):
        self.server = server
        
        # Convites ativos por ID
        self.active_invites: Dict[str, Invite] = {}
        
        # Convites pendentes por usuário
        self.user_invites: Dict[str, set] = {}
        
        # Task de limpeza
        self.cleanup_task = None
        
        # Stats
        self.stats = {
            'total_sent': 0,
            'total_accepted': 0,
            'total_rejected': 0,
            'total_cancelled': 0,
            'total_expired': 0
        }
    
    async def start(self):
        """Inicia o manager"""
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("InviteManager started")
    
    async def stop(self):
        """Para o manager"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("InviteManager stopped")
    
    async def send_invite(self, sender_client, target_id, invite_type: InviteType, 
                         data: dict = None, expiry_seconds=120):
        """
        Envia um convite.
        
        Args:
            sender_client: Cliente que envia
            target_id: ID do destinatário
            invite_type: Tipo de convite
            data: Dados adicionais
            expiry_seconds: Tempo de expiração
            
        Returns:
            str: ID do convite ou None se falhou
        """
        # Validações
        if not sender_client.is_authenticated:
            logger.warning("Unauthenticated invite attempt")
            return None
        
        if sender_client.user_id == target_id:
            logger.warning("Cannot invite self")
            return None
        
        # Verifica se target existe
        target_exists = self.server.db.get_userno(target_id)
        if not target_exists:
            logger.warning(f"Target user does not exist: {target_id}")
            return None
        
        # Cria convite
        invite_id = str(uuid.uuid4())[:8]
        invite = Invite(
            invite_id,
            sender_client.user_id,
            target_id,
            invite_type,
            data,
            expiry_seconds
        )
        
        # Armazena
        self.active_invites[invite_id] = invite
        
        if target_id not in self.user_invites:
            self.user_invites[target_id] = set()
        self.user_invites[target_id].add(invite_id)
        
        self.stats['total_sent'] += 1
        
        # Notifica destinatário se online
        target_session = self.server.user_sessions.get(target_id)
        if target_session:
            await self._send_invite_notification(target_session, invite)
        
        logger.info(f"[INVITE] {sender_client.user_id} -> {target_id} ({invite_type.name})")
        
        return invite_id
    
    async def accept_invite(self, client, invite_id: str):
        """
        Aceita um convite.
        
        Args:
            client: Cliente que aceita
            invite_id: ID do convite
            
        Returns:
            bool: True se aceito com sucesso
        """
        invite = self.active_invites.get(invite_id)
        
        if not invite:
            logger.warning(f"Invite not found: {invite_id}")
            return False
        
        if invite.target_id != client.user_id:
            logger.warning(f"Unauthorized accept attempt: {client.user_id}")
            return False
        
        if invite.is_expired():
            logger.warning(f"Invite expired: {invite_id}")
            await self._expire_invite(invite)
            return False
        
        # Atualiza status
        invite.status = InviteStatus.ACCEPTED
        self.stats['total_accepted'] += 1
        
        # Processa baseado no tipo
        success = await self._process_accept(client, invite)
        
        if success:
            # Notifica remetente
            sender_session = self.server.user_sessions.get(invite.sender_id)
            if sender_session:
                await self._send_accept_notification(sender_session, invite)
            
            logger.info(f"[INVITE ACCEPT] {client.user_id} accepted {invite_id}")
        
        # Remove convite
        self._remove_invite(invite_id)
        
        return success
    
    async def reject_invite(self, client, invite_id: str, reason: str = ""):
        """
        Rejeita um convite.
        
        Args:
            client: Cliente que rejeita
            invite_id: ID do convite
            reason: Razão (opcional)
            
        Returns:
            bool: True se rejeitado com sucesso
        """
        invite = self.active_invites.get(invite_id)
        
        if not invite:
            return False
        
        if invite.target_id != client.user_id:
            return False
        
        invite.status = InviteStatus.REJECTED
        self.stats['total_rejected'] += 1
        
        # Notifica remetente
        sender_session = self.server.user_sessions.get(invite.sender_id)
        if sender_session:
            await self._send_reject_notification(sender_session, invite, reason)
        
        logger.info(f"[INVITE REJECT] {client.user_id} rejected {invite_id}")
        
        self._remove_invite(invite_id)
        return True
    
    async def cancel_invite(self, client, invite_id: str):
        """
        Cancela um convite.
        
        Args:
            client: Cliente que cancela
            invite_id: ID do convite
            
        Returns:
            bool: True se cancelado com sucesso
        """
        invite = self.active_invites.get(invite_id)
        
        if not invite:
            return False
        
        if invite.sender_id != client.user_id:
            return False
        
        invite.status = InviteStatus.CANCELLED
        self.stats['total_cancelled'] += 1
        
        # Notifica destinatário
        target_session = self.server.user_sessions.get(invite.target_id)
        if target_session:
            await self._send_cancel_notification(target_session, invite)
        
        logger.info(f"[INVITE CANCEL] {client.user_id} cancelled {invite_id}")
        
        self._remove_invite(invite_id)
        return True
    
    async def _process_accept(self, client, invite: Invite):
        """Processa aceitação baseado no tipo de convite"""
        if invite.invite_type == InviteType.BUDDY:
            # Adiciona como amigo
            success = self.server.db.add_buddy(invite.target_id, invite.sender_id)
            if success:
                # Adiciona recíproco
                self.server.db.add_buddy(invite.sender_id, invite.target_id)
            return success
        
        elif invite.invite_type == InviteType.GAME:
            # Envia dados de conexão ao jogo
            await self._send_game_join_info(client, invite.data)
            return True
        
        return True
    
    async def _send_invite_notification(self, client, invite: Invite):
        """Envia notificação de convite recebido"""
        pkt = PacketBuilder(self.PKT_INVITE_RECEIVE)
        pkt.write_string(invite.invite_id)
        pkt.write_byte(invite.invite_type.value)
        pkt.write_string(invite.sender_id)
        pkt.write_int(int(invite.time_remaining()))
        
        # Dados adicionais
        if invite.invite_type == InviteType.GAME:
            pkt.write_string(invite.data.get('room_name', 'Game'))
            pkt.write_int(invite.data.get('room_id', 0))
        
        await client.send_packet(pkt.build())
    
    async def _send_accept_notification(self, client, invite: Invite):
        """Notifica remetente que convite foi aceito"""
        pkt = PacketBuilder(self.PKT_INVITE_ACCEPT)
        pkt.write_string(invite.invite_id)
        pkt.write_string(invite.target_id)
        
        await client.send_packet(pkt.build())
    
    async def _send_reject_notification(self, client, invite: Invite, reason: str):
        """Notifica remetente que convite foi rejeitado"""
        pkt = PacketBuilder(self.PKT_INVITE_REJECT)
        pkt.write_string(invite.invite_id)
        pkt.write_string(invite.target_id)
        pkt.write_string(reason)
        
        await client.send_packet(pkt.build())
    
    async def _send_cancel_notification(self, client, invite: Invite):
        """Notifica destinatário que convite foi cancelado"""
        pkt = PacketBuilder(self.PKT_INVITE_CANCEL)
        pkt.write_string(invite.invite_id)
        
        await client.send_packet(pkt.build())
    
    async def _send_game_join_info(self, client, game_data: dict):
        """Envia informações para conectar ao jogo"""
        pkt = PacketBuilder(0xB000)  # GAME_JOIN_INFO
        pkt.write_string(game_data.get('server_ip', '127.0.0.1'))
        pkt.write_int(game_data.get('server_port', 8372))
        pkt.write_int(game_data.get('room_id', 0))
        pkt.write_string(game_data.get('room_name', 'Game'))
        
        await client.send_packet(pkt.build())
    
    async def _expire_invite(self, invite: Invite):
        """Marca convite como expirado e notifica"""
        invite.status = InviteStatus.EXPIRED
        self.stats['total_expired'] += 1
        
        # Notifica ambos
        target_session = self.server.user_sessions.get(invite.target_id)
        if target_session:
            pkt = PacketBuilder(self.PKT_INVITE_EXPIRED)
            pkt.write_string(invite.invite_id)
            await target_session.send_packet(pkt.build())
        
        logger.info(f"[INVITE EXPIRED] {invite.invite_id}")
    
    def _remove_invite(self, invite_id: str):
        """Remove convite do sistema"""
        invite = self.active_invites.pop(invite_id, None)
        if invite:
            if invite.target_id in self.user_invites:
                self.user_invites[invite.target_id].discard(invite_id)
    
    async def _cleanup_loop(self):
        """Loop de limpeza de convites expirados"""
        try:
            while True:
                await asyncio.sleep(30)  # Check a cada 30s
                
                expired = []
                for invite_id, invite in list(self.active_invites.items()):
                    if invite.is_expired():
                        expired.append(invite)
                
                for invite in expired:
                    await self._expire_invite(invite)
                    self._remove_invite(invite.invite_id)
                
                if expired:
                    logger.debug(f"Cleaned up {len(expired)} expired invites")
                
        except asyncio.CancelledError:
            logger.info("Invite cleanup loop cancelled")
    
    def get_user_invites(self, user_id: str):
        """Retorna convites pendentes de um usuário"""
        invite_ids = self.user_invites.get(user_id, set())
        return [self.active_invites[iid] for iid in invite_ids if iid in self.active_invites]
    
    def get_stats(self):
        """Retorna estatísticas"""
        return {
            **self.stats,
            'active_invites': len(self.active_invites)
        }