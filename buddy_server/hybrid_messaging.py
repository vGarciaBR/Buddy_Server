import asyncio
import logging
from enum import IntEnum
from typing import Optional

from .packets import PacketBuilder
from .p2p_manager import P2PManager
from .tunneling import TunnelingManager
from .dynamic_crypto import HybridCrypto

logger = logging.getLogger(__name__)

class MessageRoute(IntEnum):
    """Rotas possíveis para uma mensagem"""
    P2P_DIRECT = 0       # P2P direto (mais rápido)
    SERVER_RELAY = 1     # Através do servidor (fallback)
    OFFLINE_QUEUE = 2    # Destinatário offline

class HybridMessagingManager:
    """
    Gerenciador híbrido que combina P2P e relay do servidor.
    
    Fluxo de decisão:
    1. Tenta P2P se conexão estabelecida
    2. Fallback para relay do servidor
    3. Se offline, salva no banco
    
    Características:
    - Roteamento inteligente
    - Failover automático
    - Criptografia adaptativa
    - Monitoramento de qualidade
    """
    
    def __init__(self, server):
        self.server = server
        
        # Managers
        self.p2p_manager = P2PManager(server)
        self.tunneling_manager = server.tunneling_manager  # Já existe
        
        # Criptografia híbrida
        self.crypto = HybridCrypto(use_dynamic=True)
        
        # Configurações
        self.prefer_p2p = True  # Preferir P2P quando possível
        self.p2p_fallback_threshold = 3  # Falhas antes de desistir de P2P
        
        # Estatísticas por rota
        self.route_stats = {
            MessageRoute.P2P_DIRECT: {'count': 0, 'bytes': 0, 'failures': 0},
            MessageRoute.SERVER_RELAY: {'count': 0, 'bytes': 0, 'failures': 0},
            MessageRoute.OFFLINE_QUEUE: {'count': 0, 'bytes': 0, 'failures': 0}
        }
        
        # Cache de falhas P2P (para evitar tentar repetidamente)
        self.p2p_failure_cache = {}  # (sender, target) -> fail_count
    
    async def start(self):
        """Inicia o manager"""
        await self.p2p_manager.start()
        logger.info("HybridMessagingManager started")
    
    async def stop(self):
        """Para o manager"""
        await self.p2p_manager.stop()
        logger.info("HybridMessagingManager stopped")
    
    async def send_message(self, sender_client, target_id: str, 
                          packet_id: int, payload: bytes) -> MessageRoute:
        """
        Envia mensagem usando a melhor rota disponível.
        
        Args:
            sender_client: Cliente remetente
            target_id: ID do destinatário
            packet_id: ID do pacote
            payload: Dados da mensagem
            
        Returns:
            MessageRoute: Rota utilizada
        """
        sender_id = sender_client.user_id
        
        # 1. Verifica se destinatário está online
        target_session = self.server.user_sessions.get(target_id)
        
        if not target_session:
            # Offline - salva no banco
            return await self._route_offline(sender_id, target_id, packet_id, payload)
        
        # 2. Tenta P2P se habilitado e viável
        if self.prefer_p2p and self._should_try_p2p(sender_id, target_id):
            route = await self._route_p2p(sender_id, target_id, packet_id, payload)
            
            if route == MessageRoute.P2P_DIRECT:
                return route
            
            # P2P falhou, registra falha
            self._record_p2p_failure(sender_id, target_id)
        
        # 3. Fallback para relay do servidor
        return await self._route_relay(sender_client, target_id, packet_id, payload)
    
    def _should_try_p2p(self, sender_id: str, target_id: str) -> bool:
        """
        Decide se deve tentar P2P baseado em histórico de falhas.
        
        Returns:
            bool: True se deve tentar
        """
        cache_key = (sender_id, target_id)
        
        if cache_key not in self.p2p_failure_cache:
            return True
        
        fail_count = self.p2p_failure_cache[cache_key]
        
        # Se falhou muito, desiste por um tempo
        if fail_count >= self.p2p_fallback_threshold:
            logger.debug(f"[HYBRID] Skipping P2P due to {fail_count} failures: {sender_id} -> {target_id}")
            return False
        
        return True
    
    def _record_p2p_failure(self, sender_id: str, target_id: str):
        """Registra falha de P2P"""
        cache_key = (sender_id, target_id)
        
        if cache_key not in self.p2p_failure_cache:
            self.p2p_failure_cache[cache_key] = 0
        
        self.p2p_failure_cache[cache_key] += 1
        
        fail_count = self.p2p_failure_cache[cache_key]
        logger.debug(f"[HYBRID] P2P failure #{fail_count}: {sender_id} -> {target_id}")
    
    def reset_p2p_failures(self, sender_id: str, target_id: str):
        """Reseta contador de falhas (chamado quando P2P funciona)"""
        cache_key = (sender_id, target_id)
        self.p2p_failure_cache.pop(cache_key, None)
    
    async def _route_p2p(self, sender_id: str, target_id: str, 
                        packet_id: int, payload: bytes) -> MessageRoute:
        """
        Tenta enviar via P2P.
        
        Returns:
            MessageRoute: P2P_DIRECT se sucesso, senão outro
        """
        # Verifica se já tem conexão P2P
        has_p2p = self.p2p_manager.should_use_p2p(sender_id, target_id)
        
        if not has_p2p:
            # Tenta estabelecer P2P
            logger.debug(f"[HYBRID] No P2P connection, attempting to establish: {sender_id} -> {target_id}")
            
            # Isso é assíncrono e pode levar tempo
            # Por enquanto, retorna para usar relay imediatamente
            # Em produção, você poderia:
            # 1. Enqueue e aguardar P2P
            # 2. Ou enviar via relay mas tentar P2P para próximas
            
            # Inicia negociação P2P em background
            sender_session = self.server.user_sessions.get(sender_id)
            if sender_session:
                asyncio.create_task(self.p2p_manager.request_p2p(sender_session, target_id))
            
            # Por enquanto, usa relay
            return MessageRoute.SERVER_RELAY
        
        # Tenta enviar via P2P
        try:
            # Criptografa com crypto dinâmico
            encrypted_payload = self.crypto.encrypt(payload, use_p2p=True)
            
            success = await self.p2p_manager.send_via_p2p(
                sender_id, target_id, packet_id, encrypted_payload
            )
            
            if success:
                # Sucesso! Atualiza stats
                self.route_stats[MessageRoute.P2P_DIRECT]['count'] += 1
                self.route_stats[MessageRoute.P2P_DIRECT]['bytes'] += len(payload)
                
                # Reseta falhas
                self.reset_p2p_failures(sender_id, target_id)
                
                logger.info(f"[HYBRID] âœ… P2P: {sender_id} -> {target_id} ({len(payload)} bytes)")
                return MessageRoute.P2P_DIRECT
            else:
                # Falhou
                self.route_stats[MessageRoute.P2P_DIRECT]['failures'] += 1
                logger.warning(f"[HYBRID] P2P send failed: {sender_id} -> {target_id}")
                return MessageRoute.SERVER_RELAY
                
        except Exception as e:
            logger.error(f"[HYBRID] P2P error: {e}")
            self.route_stats[MessageRoute.P2P_DIRECT]['failures'] += 1
            return MessageRoute.SERVER_RELAY
    
    async def _route_relay(self, sender_client, target_id: str, 
                          packet_id: int, payload: bytes) -> MessageRoute:
        """
        Envia via relay do servidor (tunneling).
        
        Returns:
            MessageRoute: SERVER_RELAY se sucesso, OFFLINE_QUEUE se falhou
        """
        try:
            # Usa o TunnelingManager existente
            success = await self.tunneling_manager.tunnel_packet(
                sender_client, target_id, packet_id, payload
            )
            
            if success:
                self.route_stats[MessageRoute.SERVER_RELAY]['count'] += 1
                self.route_stats[MessageRoute.SERVER_RELAY]['bytes'] += len(payload)
                
                logger.info(f"[HYBRID] ðŸ"¦ RELAY: {sender_client.user_id} -> {target_id}")
                return MessageRoute.SERVER_RELAY
            else:
                # Falhou (provavelmente salvou offline)
                self.route_stats[MessageRoute.SERVER_RELAY]['failures'] += 1
                return MessageRoute.OFFLINE_QUEUE
                
        except Exception as e:
            logger.error(f"[HYBRID] Relay error: {e}")
            self.route_stats[MessageRoute.SERVER_RELAY]['failures'] += 1
            return MessageRoute.OFFLINE_QUEUE
    
    async def _route_offline(self, sender_id: str, target_id: str, 
                            packet_id: int, payload: bytes) -> MessageRoute:
        """
        Salva mensagem offline no banco.
        
        Returns:
            MessageRoute: OFFLINE_QUEUE
        """
        try:
            body_hex = payload.hex()
            
            success = self.server.db.save_packet(
                sender_id, target_id, packet_id, body_hex
            )
            
            if success:
                self.route_stats[MessageRoute.OFFLINE_QUEUE]['count'] += 1
                self.route_stats[MessageRoute.OFFLINE_QUEUE]['bytes'] += len(payload)
                
                logger.info(f"[HYBRID] ðŸ'¾ OFFLINE: {sender_id} -> {target_id} (saved to DB)")
            else:
                self.route_stats[MessageRoute.OFFLINE_QUEUE]['failures'] += 1
                logger.error(f"[HYBRID] Failed to save offline message")
            
            return MessageRoute.OFFLINE_QUEUE
            
        except Exception as e:
            logger.error(f"[HYBRID] Offline save error: {e}")
            self.route_stats[MessageRoute.OFFLINE_QUEUE]['failures'] += 1
            return MessageRoute.OFFLINE_QUEUE
    
    def get_route_quality(self, sender_id: str, target_id: str) -> dict:
        """
        Retorna qualidade/status da rota para um par de usuários.
        
        Returns:
            dict: {
                'preferred_route': MessageRoute,
                'p2p_available': bool,
                'p2p_latency': float (ms),
                'relay_latency': float (ms),
                'target_online': bool
            }
        """
        target_online = target_id in self.server.user_sessions
        p2p_available = self.p2p_manager.should_use_p2p(sender_id, target_id)
        
        # TODO: Implementar medição real de latência
        p2p_latency = 20.0 if p2p_available else None
        relay_latency = 50.0 if target_online else None
        
        if p2p_available:
            preferred = MessageRoute.P2P_DIRECT
        elif target_online:
            preferred = MessageRoute.SERVER_RELAY
        else:
            preferred = MessageRoute.OFFLINE_QUEUE
        
        return {
            'preferred_route': preferred,
            'p2p_available': p2p_available,
            'p2p_latency': p2p_latency,
            'relay_latency': relay_latency,
            'target_online': target_online
        }
    
    def get_stats(self) -> dict:
        """
        Retorna estatísticas completas.
        
        Returns:
            dict: Estatísticas de todas as rotas
        """
        total_messages = sum(s['count'] for s in self.route_stats.values())
        total_bytes = sum(s['bytes'] for s in self.route_stats.values())
        
        # Calcula percentuais
        route_percentages = {}
        for route, stats in self.route_stats.items():
            if total_messages > 0:
                percentage = (stats['count'] / total_messages) * 100
            else:
                percentage = 0.0
            
            route_percentages[route.name] = {
                'count': stats['count'],
                'bytes': stats['bytes'],
                'failures': stats['failures'],
                'percentage': f"{percentage:.1f}%"
            }
        
        # Stats do P2P manager
        p2p_stats = self.p2p_manager.get_stats()
        
        return {
            'total_messages': total_messages,
            'total_bytes': total_bytes,
            'routes': route_percentages,
            'p2p': p2p_stats,
            'p2p_failure_cache_size': len(self.p2p_failure_cache)
        }
    
    def print_stats(self):
        """Imprime estatísticas no console"""
        stats = self.get_stats()
        
        print("\n" + "="*60)
        print("📊 HYBRID MESSAGING STATISTICS")
        print("="*60)
        print(f"Total Messages: {stats['total_messages']}")
        print(f"Total Bytes: {stats['total_bytes']:,}")
        print()
        
        print("Route Distribution:")
        for route_name, route_stats in stats['routes'].items():
            print(f"  {route_name}:")
            print(f"    Count: {route_stats['count']} ({route_stats['percentage']})")
            print(f"    Bytes: {route_stats['bytes']:,}")
            print(f"    Failures: {route_stats['failures']}")
        print()
        
        print("P2P Stats:")
        p2p = stats['p2p']
        print(f"  Attempts: {p2p['p2p_attempts']}")
        print(f"  Successful: {p2p['p2p_successful']}")
        print(f"  Success Rate: {p2p['success_rate']}")
        print(f"  Active Connections: {p2p['active_p2p_connections']}")
        print(f"  Relay Mode: {p2p['relay_mode_connections']}")
        print("="*60 + "\n")
    
    async def enable_p2p_for_pair(self, user_a: str, user_b: str):
        """
        Força estabelecimento de P2P entre dois usuários.
        Útil para quando ambos entram em um jogo juntos.
        """
        logger.info(f"[HYBRID] Forcing P2P establishment: {user_a} <-> {user_b}")
        
        session_a = self.server.user_sessions.get(user_a)
        session_b = self.server.user_sessions.get(user_b)
        
        if not session_a or not session_b:
            logger.warning(f"[HYBRID] Cannot establish P2P, one or both users offline")
            return False
        
        # Inicia negociação de ambos os lados
        await self.p2p_manager.request_p2p(session_a, user_b)
        await asyncio.sleep(0.5)
        await self.p2p_manager.request_p2p(session_b, user_a)
        
        logger.info(f"[HYBRID] P2P negotiation started for pair")
        return True


# =============================================================================
# EXEMPLO DE USO
# =============================================================================

async def demo_hybrid_messaging():
    """Demonstra o sistema híbrido"""
    print("=== Hybrid Messaging Demo ===\n")
    
    # Simulação de servidor
    class MockServer:
        def __init__(self):
            self.user_sessions = {}
            self.db = None
            self.tunneling_manager = None
    
    server = MockServer()
    hybrid = HybridMessagingManager(server)
    
    print("Stats before any messages:")
    hybrid.print_stats()
    
    print("\nDemo complete. In production:")
    print("1. Messages automatically routed via P2P when available")
    print("2. Falls back to server relay if P2P fails")
    print("3. Saves offline if recipient not connected")
    print("4. Encrypted differently for P2P vs relay")
    print("5. Tracks quality metrics for intelligent routing")


if __name__ == "__main__":
    asyncio.run(demo_hybrid_messaging())