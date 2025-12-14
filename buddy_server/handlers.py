from .constants import *
from .packets import Packet, PacketBuilder, PacketReader
import logging

logger = logging.getLogger(__name__)

async def handle_packet(client, packet_id, header, payload):
    reader = PacketReader(payload)
    
    if packet_id == SVC_LOGIN_REQ:
        await handle_login(client, reader)
    elif packet_id == SVC_ADD_BUDDY:
        await handle_add_buddy(client, reader)
    elif packet_id == SVC_REMOVE_BUDDY:
        await handle_remove_buddy(client, reader)
    elif packet_id == SVC_GROUP_BUDDY:
        await handle_group_buddy(client, reader)
    elif packet_id == SVC_RENAME_GROUP:
        await handle_rename_group(client, reader)
    elif packet_id == SVC_USER_STATE:
        await handle_user_state(client, reader)
    elif packet_id == SVC_SEARCH:
        await handle_search(client, reader)
    elif packet_id == SVC_TUNNEL_PACKET:
        await handle_tunnel_packet(client, reader)
    elif packet_id == 0xA110: # Chat Message
        await handle_buddy_chat(client, payload)
    elif packet_id == 0xA200: # Add Buddy / Invite
        await handle_buddy_action(client, payload)
    elif packet_id == 0xA510: # Status Update
        await handle_client_status_update(client, PacketReader(payload))
    elif packet_id == 0xA502 or packet_id == 0xA500: # Heartbeat
        await handle_heartbeat(client, PacketReader(payload))
    elif packet_id == 0x1030: # Buddy Note
        await handle_buddy_note(client, PacketReader(payload))
    elif packet_id == 0xA000: # BUDDY_LOGIN
        await handle_buddy_login(client, PacketReader(payload))
    
    # ========== HANDLERS INVITE SYSTEM ==========
    elif packet_id == 0xA300:  # Send Invite
        await handle_send_invite(client, PacketReader(payload))
    elif packet_id == 0xA302:  # Accept Invite
        await handle_accept_invite(client, PacketReader(payload))
    elif packet_id == 0xA303:  # Reject Invite
        await handle_reject_invite(client, PacketReader(payload))
    elif packet_id == 0xA304:  # Cancel Invite
        await handle_cancel_invite(client, PacketReader(payload))
    
    # ========== HANDLERS STATUS SYSTEM ==========
    elif packet_id == 0xA511:  # Status Query
        await handle_status_query(client, PacketReader(payload))
    
    # ========== HANDLERS GAME INTEGRATION ==========
    elif packet_id == 0xB100:  # Enter Game
        await handle_enter_game(client, PacketReader(payload))
    elif packet_id == 0xB101:  # Leave Game
        await handle_leave_game(client, PacketReader(payload))
    
    # ========== NOVOS HANDLERS P2P ==========
    elif packet_id == 0xC000:  # PKT_P2P_REQUEST
        await handle_p2p_request(client, PacketReader(payload))
    elif packet_id == 0xC002:  # PKT_P2P_ANSWER
        await handle_p2p_answer(client, PacketReader(payload))
    
    # ========== HANDLERS SERVER/BROKER (Infrastructure) ==========
    # IDs baseados na análise do binário GunBoundBroker3.exe
    elif packet_id == 0x3000 or packet_id == 0x3010: # SVC_CMD_SETVERSION / STATUS match
         # Broker muitas vezes usa ranges 0x3xxx ou similares para comandos internos
         # Precisamos checar o dump para IDs exatos se soubermos, mas vamos logar e aceitar
         logger.info(f"⚡ [SERVER COMMAND] Recebido possível comando de servidor: {hex(packet_id)}")
         
    # Se receber SVC_CMD_SETVERSION (geralmente troca de versão)
    elif packet_id == 0x6be9c: # Visto no dump como SVC_CMD_SETVERSION (offset, não ID)
         pass # Placeholder, offsets != IDs
    
    # Comandos genéricos de servidor que podem aparecer
    elif packet_id in [0xA0F0, 0xA0F1, 0xA0F2]: # Exemplo de IDs de Admin
         logger.info(f"🔧 [ADMIN/SERVER] Command {hex(packet_id)} accepted from {client.ip}")
         
    else:
        # Se vier de localhost e for desconhecido, 99% de chance de ser o Broker ou GameServer
        if client.ip and client.ip[0] == '127.0.0.1':
             logger.warning(f"⚠️ [BROKER/SERVER?] Packet {hex(packet_id)} from LOCALHOST ({client.ip[1]}) not handled!")
             logger.warning(f"   Payload Hex: {payload.hex()[:50]}...")
        else:
             logger.warning(f"Unknown or Unhandled Packet ID: {hex(packet_id)} from {client.ip}")

# ============================================================================
# NOVOS HANDLERS P2P
# ============================================================================

async def handle_p2p_request(client, reader):
    """Cliente solicita estabelecer conexão P2P com outro usuário"""
    try:
        target_id = reader.read_string()
        
        logger.info(f"[P2P REQUEST] {client.user_id} wants P2P with {target_id}")
        
        success = await client.server.p2p_manager.request_p2p(client, target_id)
        
        if success:
            logger.info(f"✅ [P2P] Negotiation started: {client.user_id} <-> {target_id}")
        else:
            logger.warning(f"⚠️ [P2P] Failed to start negotiation")
            
    except Exception as e:
        logger.error(f"❌ [P2P REQUEST ERROR] {e}")
        import traceback
        logger.error(traceback.format_exc())

async def handle_p2p_answer(client, reader):
    """Cliente responde se conseguiu estabelecer P2P"""
    try:
        await client.server.p2p_manager.handle_p2p_answer(client, reader.data)
    except Exception as e:
        logger.error(f"❌ [P2P ANSWER ERROR] {e}")

# ============================================================================
# CHAT HANDLER - AGORA USA P2P QUANDO DISPONÍVEL
# ============================================================================

async def handle_buddy_chat(client, payload):
    """
    Handler de chat com SUPORTE A P2P.
    Tenta P2P primeiro, fallback para relay.
    """
    try:
        logger.info(f"[CHAT DEBUG] ============================================")
        logger.info(f"[CHAT DEBUG] RAW Payload ({len(payload)} bytes):")
        logger.info(f"[CHAT DEBUG] HEX: {payload.hex()}")
        
        if b'\x00' not in payload:
            logger.error("[CHAT] ❌ Payload inválido: sem null terminator")
            return
        
        parts = payload.split(b'\x00', 1)
        target_id_raw = parts[0]
        target_id = target_id_raw.decode('latin-1', errors='ignore').strip()
        
        logger.info(f"[CHAT DEBUG] Target ID: '{target_id}'")
        logger.info(f"[CHAT DEBUG] Sender: '{client.user_id}'")
        
        if not target_id:
            logger.error("[CHAT] ❌ Target ID vazio!")
            return
        
        if target_id == client.user_id:
            logger.warning(f"[CHAT] ⚠️ Usuário tentando enviar para si mesmo!")
            
            if len(payload) >= 9:
                alt_metadata = payload[:9]
                alt_remainder = payload[9:]
                
                if b'\x00' in alt_remainder:
                    alt_parts = alt_remainder.split(b'\x00', 1)
                    alt_target = alt_parts[0].decode('latin-1', errors='ignore').strip()
                    
                    if alt_target and alt_target != client.user_id:
                        logger.info(f"[CHAT] ✅ Formato alternativo! Target: {alt_target}")
                        target_id = alt_target
                        metadata = alt_metadata
                        message_data = alt_parts[1] if len(alt_parts) > 1 else b''
                    else:
                        return
                else:
                    return
            else:
                return
        else:
            if len(parts) < 2:
                logger.error("[CHAT] ❌ Payload inválido: sem dados após target")
                return
            
            remainder = parts[1]
            
            if len(remainder) < 9:
                logger.error(f"[CHAT] ❌ Resto muito curto ({len(remainder)} bytes)")
                return
            
            metadata = remainder[:9]
            message_data = remainder[9:]
            
            # --- FIX CHAT INVISÍVEL ---
            # Remove bytes nulos (0x00) do INÍCIO da mensagem, que causam chat vazio
            while len(message_data) > 0 and message_data[0] == 0:
                message_data = message_data[1:]
                
            if len(message_data) == 0:
                 # Se sobrou nada, restaura pelo menos um espaço ou ignora
                 # message_data = b' ' 
                 pass
        
        # logger.info(f"[CHAT DEBUG] ✅ Parse OK:")
        # logger.info(f"[CHAT DEBUG]   Sender: '{client.user_id}'")
        # logger.info(f"[CHAT DEBUG]   Target: '{target_id}'")
        # logger.info(f"[CHAT DEBUG]   Metadata: {metadata.hex()}")
        # logger.info(f"[CHAT DEBUG]   Message (Clean): {message_data.hex()}")
        
        try:
            msg_text = message_data.decode('utf-8', errors='ignore')
            logger.info(f"[CHAT] 💬 {client.user_id} -> {target_id}: '{msg_text}'")
        except:
            logger.info(f"[CHAT] 💬 {client.user_id} -> {target_id}: <binary data>")
        
        # Reconstrói payload para o destinatário
        # Formato Padrão: SENDER_ID + NULL + METADATA + MESSAGE_CLEAN
        
        sender_bytes = client.user_id.encode('latin-1')
        # metadata já temos
        # message_data já limpamos
        
        output_payload = bytearray()
        output_payload.extend(sender_bytes)
        output_payload.append(0) # Null terminator for Sender
        output_payload.extend(metadata)
        output_payload.extend(message_data)
        
        logger.info(f"[CHAT DEBUG] Tamanho: Original={len(payload)}, Output={len(output_payload)}")
        logger.info(f"[CHAT DEBUG] Output HEX: {bytes(output_payload).hex()}")
        logger.info(f"[CHAT DEBUG] ============================================")
        
        # ========== VERIFICA SE DESTINATÁRIO ESTÁ ONLINE ==========
        target_session = client.server.user_sessions.get(target_id)
        
        if not target_session:
            logger.warning(f"[CHAT] ⚠️ Target {target_id} offline, salvando mensagem")
            # Salva offline
            success = await client.server.tunneling_manager.tunnel_packet(
                client,
                target_id,
                0xA110,
                bytes(output_payload)
            )
            if success:
                logger.info(f"💾 [CHAT OFFLINE] Mensagem salva: {client.user_id} -> {target_id}")
            return
        
        # ========== INICIA P2P EM BACKGROUND (se ainda não existe) ==========
        p2p_available = client.server.p2p_manager.should_use_p2p(client.user_id, target_id)
        
        if not p2p_available:
            logger.info(f"[CHAT] 🔗 Iniciando negociação P2P em background...")
            import asyncio
            asyncio.create_task(client.server.p2p_manager.request_p2p(client, target_id))
        
        # ========== TENTA P2P (se disponível) ==========
        if p2p_available:
            logger.info(f"[CHAT] 🔗 Tentando enviar via P2P...")
            p2p_success = await client.server.p2p_manager.send_via_p2p(
                client.user_id,
                target_id,
                0xA110,
                bytes(output_payload)
            )
            
            if p2p_success:
                logger.info(f"✅ [CHAT P2P] Mensagem enviada: {client.user_id} -> {target_id}")
                return
            else:
                logger.warning(f"⚠️ [CHAT P2P] Falhou, usando relay...")
        
        # ========== FALLBACK: USA RELAY DO SERVIDOR ==========
        # ENVIA DIRETO PARA O TARGET SESSION (não usa tunneling_manager)
        try:
            # Log detalhado do que está sendo enviado
            logger.info(f"[CHAT DEBUG] Construindo pacote para envio:")
            logger.info(f"[CHAT DEBUG]   PacketID: 0xA110")
            logger.info(f"[CHAT DEBUG]   Payload size: {len(output_payload)} bytes")
            logger.info(f"[CHAT DEBUG]   Payload HEX: {bytes(output_payload).hex()}")
            
            # Parse para verificar
            verify_parts = bytes(output_payload).split(b'\x00', 1)
            verify_sender = verify_parts[0].decode('latin-1', errors='ignore').strip()
            verify_remainder = verify_parts[1] if len(verify_parts) > 1 else b''
            verify_metadata = verify_remainder[:9] if len(verify_remainder) >= 9 else b''
            verify_message = verify_remainder[9:] if len(verify_remainder) > 9 else b''
            
            logger.info(f"[CHAT DEBUG] Verificação do payload construído:")
            logger.info(f"[CHAT DEBUG]   Sender field: '{verify_sender}' ({len(verify_parts[0])} bytes)")
            logger.info(f"[CHAT DEBUG]   Metadata: {verify_metadata.hex()} ({len(verify_metadata)} bytes)")
            logger.info(f"[CHAT DEBUG]   Message: '{verify_message.decode('latin-1', errors='ignore')}' ({len(verify_message)} bytes)")
            
            # Constrói e envia pacote
            tunnel_packet = PacketBuilder(0xA110)
            tunnel_packet.buffer = bytearray(output_payload)
            
            packet_data = tunnel_packet.build()
            logger.info(f"[CHAT DEBUG] Pacote final montado: {len(packet_data.to_bytes())} bytes")
            
            await target_session.send_packet(packet_data)
            
            logger.info(f"✅ [CHAT RELAY] Mensagem enviada: {client.user_id} -> {target_id}")
            logger.info(f"[CHAT DEBUG] Target IP: {target_session.ip}")
            
        except Exception as e:
            logger.error(f"❌ [CHAT RELAY] Erro ao enviar: {e}")
            import traceback
            logger.error(f"[CHAT DEBUG] Traceback:\n{traceback.format_exc()}")
            
            # Salva offline como último recurso
            body_hex = bytes(output_payload).hex()
            client.server.db.save_packet(client.user_id, target_id, 0xA110, body_hex)
            logger.info(f"💾 [CHAT] Salvo offline após falha no relay")
            
    except Exception as e:
        import traceback
        logger.error(f"❌ [CHAT ERROR] {e}")
        logger.error(f"Traceback:\n{traceback.format_exc()}")

# ============================================================================
# BUDDY ACTION HANDLER - COM P2P
# ============================================================================

async def handle_buddy_action(client, payload):
    """
    Handler genérico para Buddy Actions (Convites, etc).
    Atua como Relay Transparente: Recebe -> Repassa para o Alvo.
    """
    try:
        logger.debug(f"[BUDDY ACTION DEBUG] Payload ({len(payload)} bytes): {payload.hex()}")
        
        if b'\x00' not in payload:
            logger.error("[BUDDY ACTION] Payload inválido: sem null terminator")
            return
        
        parts = payload.split(b'\x00', 1)
        target_id_raw = parts[0]
        target_id = target_id_raw.decode('latin-1', errors='ignore').strip()
        
        if not target_id:
            logger.error("[BUDDY ACTION] Target ID vazio!")
            return

        logger.info(f"[BUDDY ACTION] {client.user_id} -> {target_id}")
        
        # Reconstrói payload padrão: SENDER + NULL + RESTO
        # O cliente original espera ver quem mandou no início do pacote
        remainder = parts[1]
        
        sender_bytes = client.user_id.encode('latin-1')
        
        output_payload = bytearray()
        output_payload.extend(sender_bytes)
        output_payload.append(0)
        output_payload.extend(remainder)
        
        # ========== VERIFICA TARGET ==========
        target_session = client.server.user_sessions.get(target_id)
        
        if not target_session:
            logger.warning(f"[BUDDY ACTION] Target {target_id} offline ou não encontrado")
            # Avisa cliente que falhou
            fail_pkt = PacketBuilder(0xA202) # Action Failed
            fail_pkt.write_int(0)
            fail_pkt.write_string(target_id)
            await client.send_packet(fail_pkt.build())
            return
            
        # ========== TENTA VIA P2P SE DISPONÍVEL ==========
        p2p_available = client.server.p2p_manager.should_use_p2p(client.user_id, target_id)
        
        if p2p_available:
            logger.info(f"[BUDDY ACTION] 🔗 Tentando via P2P...")
            success = await client.server.p2p_manager.send_via_p2p(
                client.user_id,
                target_id,
                0xA200, # Mantém ID original
                bytes(output_payload)
            )
            if success:
                logger.info("✅ [BUDDY ACTION] Enviado via P2P")
                return

        # ========== FALLBACK: RELAY DIRETO ==========
        logger.info("[BUDDY ACTION] Usando Relay do Servidor...")
        
        out_pkt = PacketBuilder(0xA200)
        out_pkt.buffer = bytearray(output_payload)
        
        await target_session.send_packet(out_pkt.build())
        logger.info(f"✅ [BUDDY ACTION RELAY] {client.user_id} -> {target_id} enviado.")

    except Exception as e:
        logger.error(f"❌ [BUDDY ACTION ERROR] {e}")
        import traceback
        logger.error(traceback.format_exc())

# ============================================================================
# OUTROS HANDLERS (mantidos do original)
# ============================================================================

async def handle_client_status_update(client, reader):
    """Handler de status com validação."""
    try:
        await client.server.status_manager.user_activity(client.user_id)
        await client.server.status_manager.handle_status_update_packet(client, reader.data)
    except Exception as e:
        logger.error(f"Error in status update: {e}")

async def handle_heartbeat(client, reader):
    """Handler de heartbeat."""
    try:
        await client.server.status_manager.user_activity(client.user_id)
        
        ack = PacketBuilder(0xA500)
        await client.send_packet(ack.build())
    except Exception as e:
        logger.error(f"Error in heartbeat: {e}")

async def handle_buddy_note(client, reader):
    logger.info("Buddy Note (0x1030) packet received - Not implemented yet")

async def send_fake_online_notification(client, fake_user_id, fake_nick):
    resp = PacketBuilder(0x1010)
    resp.write_int(1)
    
    resp.write_string(fake_nick)
    resp.write_byte(1)
    resp.write_string(fake_user_id)
    resp.write_int(0)
    
    await client.send_packet(resp.build())
    logger.info(f"Faked {fake_user_id} as ONLINE to {client.user_id}")

async def handle_buddy_login(client, reader):
    """Handler de login."""
    try:
        version = reader.read_int()
        
        raw_data = reader.data
        version_again = int.from_bytes(raw_data[:4], 'little')
        
        str_data = raw_data[4:]
        if b'\x00' in str_data:
            user_id = str_data.split(b'\x00')[0].decode('latin-1')
        else:
            user_id = str_data.decode('latin-1')
            
    except Exception as e:
        logger.error(f"Error parsing Buddy Login: {e}")
        return

    logger.info(f"BUDDY LOGIN SUCCESS: User={user_id} (Ver={version})")
    client.user_id = user_id
    client.is_authenticated = True
    client.server.register_user(user_id, client)
    
    await client.server.status_manager.user_login(user_id)
    
    if client.server.center_client:
        await client.server.center_client.notify_user_login(user_id)
    
    resp_ack = PacketBuilder(SVC_LOGIN_RESP)
    resp_ack.write_int(1)
    await client.send_packet(resp_ack.build())
    logger.info(f"Sent Login Success (0x1001) to {user_id}")

    await send_friend_list(client)

    import asyncio
    await asyncio.sleep(1.0)
    await client.server.tunneling_manager.deliver_offline_tunnels(client)

    buddies_raw = client.server.db.get_buddy_list(client.user_id)
    if buddies_raw:
        friend_ids = [b.get('friend_id', b.get('FriendId')) for b in buddies_raw if b.get('friend_id') or b.get('FriendId')]
        for fid in friend_ids:
            f_sess = client.server.user_sessions.get(fid)
            if f_sess:
                await send_friend_list(f_sess)
                logger.info(f"Notified {fid} that {client.user_id} is online")

async def send_friend_list(client):
    """Envia lista de amigos (otimizado)."""
    friend_infos = client.server.db.get_full_buddy_list(client.user_id)
    
    resp = PacketBuilder(0x1010)
    resp.write_byte(len(friend_infos))
    
    for f in friend_infos:
        f_id = f.get('Id') or f.get('id')
        f_nick = f.get('Nickname') or f.get('nickname') or f_id
        category = f.get('Category') or 'General' # Default group
        
        status = client.server.status_manager.get_status(f_id)
        
        resp.write_string(f_nick)
        resp.write_byte(status.value)
        resp.write_string(f_id)
        
        # Envia Categoria/Grupo (String)
        # Se o cliente esperar INT, isso pode precisar de ajuste, mas SQL diz String.
        # Trocando write_int(0) por write_string(category) para teste.
        # Se o cliente crashar, é porque espera Int (ID do grupo).
        # Mas baseado em dumps antigos, muitas versoes aceitam string aqui.
        try:
             # Tenta escrever como string primeiro (mais comum em versoes WC/S2)
             resp.write_string(category)
        except:
             resp.write_int(0)
        
    await client.send_packet(resp.build())
    logger.info(f"Sent Friend List ({len(friend_infos)} friends) to {client.user_id}")

async def handle_login(client, reader):
    try:
        user_id_req = reader.read_string()
    except:
        logger.error("Error parsing login packet")
        return

    logger.info(f"Login request for user {user_id_req}")
    client.user_id = user_id_req

    game_data = client.server.db.get_user_game_data(client.user_id)
    if not game_data:
        logger.warning(f"User {client.user_id} not found in Game table.")
        return

    ip_addr, port = client.ip 
    client.server.db.login_log(client.user_id, ip_addr, port, '127.0.0.1', 8352, 0)

    resp = PacketBuilder(SVC_LOGIN_RESP)
    resp.write_int(1)
    await client.send_packet(resp.build())

    buddies_raw = client.server.db.get_buddy_list(client.user_id)
    buddy_ids = [b['friend_id'] for b in buddies_raw]
    buddy_infos = client.server.db.get_users_info(buddy_ids)
    
    buddy_pkt = PacketBuilder(SVC_LOGIN_DATA)
    buddy_pkt.write_byte(len(buddy_infos))
    
    for b_info in buddy_infos:
        b_id = b_info['Id']
        b_nick = b_info['Nickname']
        
        status = client.server.status_manager.get_status(b_id)
        
        buddy_pkt.write_string(b_nick)
        buddy_pkt.write_byte(status.value)
        buddy_pkt.write_string(b_id)
        buddy_pkt.write_int(0)
        
    await client.send_packet(buddy_pkt.build())

    client.is_authenticated = True
    client.server.register_user(client.user_id, client)
    
    await client.server.status_manager.user_login(client.user_id)
    
    logger.info(f"User {client.user_id} logged in and received {len(buddy_infos)} buddies.")

async def handle_add_buddy(client, reader):
    friend_nick = reader.read_string()
    
    friend_data = client.server.db.get_user_by_nickname(friend_nick)
    if not friend_data:
        resp = PacketBuilder(SVC_ADD_BUDDY_RESP)
        resp.write_int(0)
        await client.send_packet(resp.build())
        return

    friend_id = friend_data['Id']
    
    success = client.server.db.add_buddy(client.user_id, friend_id)
    
    resp = PacketBuilder(SVC_ADD_BUDDY_RESP)
    if success:
        resp.write_int(1)
        resp.write_string(friend_id)
        resp.write_string(friend_data['Nickname'])
        logger.info(f"User {client.user_id} added friend {friend_nick} ({friend_id})")
    else:
        resp.write_int(0)
        
    await client.send_packet(resp.build())

async def handle_remove_buddy(client, reader):
    friend_id = reader.read_string()
    
    success = client.server.db.remove_buddy(client.user_id, friend_id)
    
    resp = PacketBuilder(SVC_REMOVE_BUDDY_RESP)
    if success:
        resp.write_int(1)
        resp.write_string(friend_id)
        logger.info(f"User {client.user_id} removed friend {friend_id}")
    else:
        resp.write_int(0)
        
    await client.send_packet(resp.build())

async def handle_tunnel_packet(client, reader):
    """Handler antigo de tunnel."""
    try:
        target_id = reader.read_string()
        payload_data = reader.read_remaining()

        success = await client.server.tunneling_manager.tunnel_packet(
            client,
            target_id,
            SVC_TUNNEL_PACKET,
            payload_data
        )
        
        if not success:
            logger.warning(f"Tunnel failed: {client.user_id} -> {target_id}")
            
    except Exception as e:
        logger.error(f"Error handling tunnel packet: {e}")

async def handle_group_buddy(client, reader):
    friend_id = reader.read_string()
    group_name = reader.read_string()
    
    success = client.server.db.move_buddy_to_group(client.user_id, friend_id, group_name)
    
    if success:
        logger.info(f"Moved {friend_id} to group {group_name}")

async def handle_rename_group(client, reader):
    old_name = reader.read_string()
    new_name = reader.read_string()
    
    success = client.server.db.rename_group(client.user_id, old_name, new_name)
    if success:
        logger.info(f"Renamed group {old_name} to {new_name}")
    
    resp = PacketBuilder(SVC_RENAME_GROUP_RESP)
    resp.write_int(1 if success else 0)
    await client.send_packet(resp.build())

async def handle_user_state(client, reader):
    state = reader.read_int()
    client.state = state
    
async def handle_search(client, reader):
    search_nick = reader.read_string()
    
    user_data = client.server.db.get_user_by_search_term(search_nick)
    
    resp = PacketBuilder(SVC_SEARCH_RESP)
    if user_data:
        resp.write_int(1)
        resp.write_string(user_data['Id'])
        resp.write_string(user_data['Nickname'])
    else:
        resp.write_int(0)
        
    await client.send_packet(resp.build())

# ============================================================================
# HANDLERS - INVITE SYSTEM
# ============================================================================

async def handle_send_invite(client, reader):
    """Handler para enviar convite."""
    from .invites import InviteType
    
    try:
        invite_type_value = reader.read_byte()
        target_id = reader.read_string()
        
        data = {}
        
        if invite_type_value == InviteType.GAME.value:
            data['room_name'] = reader.read_string()
            data['room_id'] = reader.read_int()
            data['server_ip'] = '127.0.0.1'
            data['server_port'] = 8372
        
        invite_type = InviteType(invite_type_value)
        
        invite_id = await client.server.invite_manager.send_invite(
            client,
            target_id,
            invite_type,
            data
        )
        
        logger.info(f"Invite sent: {client.user_id} -> {target_id} ({invite_type.name})")
        
    except Exception as e:
        logger.error(f"Error handling send invite: {e}")

async def handle_accept_invite(client, reader):
    """Handler para aceitar convite."""
    try:
        invite_id = reader.read_string()
        
        success = await client.server.invite_manager.accept_invite(client, invite_id)
        
        if success:
            logger.info(f"Invite accepted: {client.user_id} accepted {invite_id}")
        
    except Exception as e:
        logger.error(f"Error handling accept invite: {e}")

async def handle_reject_invite(client, reader):
    """Handler para rejeitar convite."""
    try:
        invite_id = reader.read_string()
        reason = ""
        try:
            reason = reader.read_string()
        except:
            pass
        
        success = await client.server.invite_manager.reject_invite(client, invite_id, reason)
        
        if success:
            logger.info(f"Invite rejected: {client.user_id} rejected {invite_id}")
        
    except Exception as e:
        logger.error(f"Error handling reject invite: {e}")

async def handle_cancel_invite(client, reader):
    """Handler para cancelar convite."""
    try:
        invite_id = reader.read_string()
        
        success = await client.server.invite_manager.cancel_invite(client, invite_id)
        
        if success:
            logger.info(f"Invite cancelled: {client.user_id} cancelled {invite_id}")
        
    except Exception as e:
        logger.error(f"Error handling cancel invite: {e}")

# ============================================================================
# HANDLERS - STATUS SYSTEM
# ============================================================================

async def handle_status_query(client, reader):
    """Handler para consulta de status."""
    try:
        target_id = reader.read_string()
        
        await client.server.status_manager.query_status(client, target_id)
        
    except Exception as e:
        logger.error(f"Error handling status query: {e}")

# ============================================================================
# HANDLERS - GAME INTEGRATION
# ============================================================================

async def handle_enter_game(client, reader):
    """Handler para quando usuário entra em jogo."""
    try:
        room_id = reader.read_int()
        room_name = reader.read_string()
        server_ip = reader.read_string()
        server_port = reader.read_int()
        
        game_data = {
            'room_id': room_id,
            'room_name': room_name,
            'server_ip': server_ip,
            'server_port': server_port
        }
        
        await client.server.status_manager.user_enter_game(client.user_id, game_data)
        
        logger.info(f"User {client.user_id} entered game: {room_name}")
        
    except Exception as e:
        logger.error(f"Error handling enter game: {e}")

async def handle_leave_game(client, reader):
    """Handler para quando usuário sai do jogo."""
    try:
        await client.server.status_manager.user_leave_game(client.user_id)
        
        logger.info(f"User {client.user_id} left game")
        
    except Exception as e:
        logger.error(f"Error handling leave game: {e}")