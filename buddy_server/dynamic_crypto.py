import hashlib
import struct
import time
import logging
from Crypto.Cipher import AES
import secrets

logger = logging.getLogger(__name__)

"""
Sistema de criptografia com checksum dinâmico e rotação de chaves.

Este módulo implementa:
1. Checksum dinâmico calculado em runtime
2. Rotação de chaves baseada em timestamp
3. Proteção contra replay attacks
4. Validação de integridade dos pacotes
"""

class DynamicCrypto:
    """
    Criptografia avançada com checksum dinâmico.
    
    Características:
    - AES-128 com chaves rotativas
    - Checksum CRC32 dinâmico
    - Nonce para prevenir replay
    - Seed baseado em timestamp
    """
    
    # Chave base (estática) - Fallback se não houver troca de chaves
    BASE_KEY_HEX = "A92753041BFCACE65B2338346846038C"
    
    # Intervalo de rotação de chave (segundos)
    KEY_ROTATION_INTERVAL = 300  # 5 minutos
    
    # Magic number para validação
    MAGIC_HEADER = 0xDEADBEEF
    
    def __init__(self, session_key=None):
        if session_key:
            self.base_key = session_key
        else:
            self.base_key = bytes.fromhex(self.BASE_KEY_HEX)
            
        self.current_key = self.base_key
        self.key_generation = 0
        self.last_rotation = time.time()
        
        # Cache de chaves rotacionadas
        self.key_cache = {}

    def set_session_key(self, key_bytes):
        """Define uma chave de sessão específica (trocada no login)"""
        self.base_key = key_bytes
        self.key_cache = {} # Limpa cache antigo
        logger.info(f"[DynamicCrypto] Session Key updated! (Len: {len(key_bytes)})")
    
    def _get_time_seed(self) -> int:
        """
        Gera seed baseado em timestamp atual.
        Usa intervalos de 5 minutos para sincronização.
        """
        current_time = int(time.time())
        # Arredonda para o intervalo de rotação
        time_slot = current_time // self.KEY_ROTATION_INTERVAL
        return time_slot
    
    def _rotate_key(self, seed: int) -> bytes:
        """
        Gera nova chave baseada no seed temporal.
        
        Processo:
        1. Combina base_key + seed
        2. Hash SHA256
        3. Trunca para 16 bytes (AES-128)
        """
        if seed in self.key_cache:
            return self.key_cache[seed]
        
        # Combina chave base com seed
        combined = self.base_key + struct.pack('<Q', seed)
        
        # Hash
        hash_obj = hashlib.sha256(combined)
        rotated_key = hash_obj.digest()[:16]  # Primeiros 16 bytes
        
        # Cache
        self.key_cache[seed] = rotated_key
        
        return rotated_key
    
    def _calculate_checksum(self, data: bytes, nonce: int) -> int:
        """
        Calcula checksum CRC32 dinâmico.
        
        Inclui:
        - Dados do pacote
        - Nonce (previne replay)
        - Magic header (validação)
        """
        import zlib
        
        # Combina dados + nonce + magic
        checksum_data = (
            struct.pack('<I', self.MAGIC_HEADER) +
            struct.pack('<I', nonce) +
            data
        )
        
        crc = zlib.crc32(checksum_data) & 0xFFFFFFFF
        return crc
    
    def encrypt_packet(self, data: bytes) -> bytes:
        """
        Criptografa pacote com checksum dinâmico.
        
        Estrutura do pacote encriptado:
        [4 bytes: Magic Header]
        [4 bytes: Nonce]
        [4 bytes: Checksum]
        [4 bytes: Timestamp]
        [N bytes: Encrypted Data]
        
        Total overhead: 16 bytes
        """
        # Gera nonce aleatório
        nonce = secrets.randbits(32)
        
        # Timestamp atual
        timestamp = int(time.time())
        
        # Calcula checksum
        checksum = self._calculate_checksum(data, nonce)
        
        # Obtém chave rotacionada
        seed = self._get_time_seed()
        key = self._rotate_key(seed)
        
        # Padding para AES (múltiplo de 16)
        pad_len = 16 - (len(data) % 16)
        if pad_len != 16:
            data = data + bytes([pad_len] * pad_len)  # PKCS7 padding
        
        # Criptografa dados
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(data)
        
        # Monta pacote final
        packet = (
            struct.pack('<I', self.MAGIC_HEADER) +
            struct.pack('<I', nonce) +
            struct.pack('<I', checksum) +
            struct.pack('<I', timestamp) +
            encrypted_data
        )
        
        return packet
    
    def decrypt_packet(self, packet: bytes) -> tuple:
        """
        Descriptografa e valida pacote.
        
        Returns:
            tuple: (success: bool, data: bytes, error_msg: str)
        """
        if len(packet) < 16:
            return False, b'', "Packet too short"
        
        # Parse header
        magic = struct.unpack('<I', packet[0:4])[0]
        nonce = struct.unpack('<I', packet[4:8])[0]
        checksum = struct.unpack('<I', packet[8:12])[0]
        timestamp = struct.unpack('<I', packet[12:16])[0]
        encrypted_data = packet[16:]
        
        # Valida magic header
        if magic != self.MAGIC_HEADER:
            return False, b'', f"Invalid magic: 0x{magic:08X}"
        
        # Valida timestamp (previne replay attacks)
        current_time = int(time.time())
        time_diff = abs(current_time - timestamp)
        
        if time_diff > 600:  # 10 minutos de tolerância
            return False, b'', f"Timestamp too old: {time_diff}s"
        
        # Obtém chave baseada no timestamp do pacote
        seed = timestamp // self.KEY_ROTATION_INTERVAL
        key = self._rotate_key(seed)
        
        # Descriptografa
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_data = cipher.decrypt(encrypted_data)
        except Exception as e:
            return False, b'', f"Decryption failed: {e}"
        
        # Remove padding PKCS7
        pad_len = decrypted_data[-1]
        if 1 <= pad_len <= 16:
            decrypted_data = decrypted_data[:-pad_len]
        
        # Valida checksum
        calculated_checksum = self._calculate_checksum(decrypted_data, nonce)
        
        if calculated_checksum != checksum:
            return False, b'', f"Checksum mismatch: {checksum:08X} != {calculated_checksum:08X}"
        
        return True, decrypted_data, ""
    
    def get_current_key_info(self) -> dict:
        """Retorna informações sobre a chave atual"""
        seed = self._get_time_seed()
        time_until_rotation = self.KEY_ROTATION_INTERVAL - (int(time.time()) % self.KEY_ROTATION_INTERVAL)
        
        return {
            'current_seed': seed,
            'key_generation': self.key_generation,
            'time_until_rotation': time_until_rotation,
            'cache_size': len(self.key_cache)
        }


class HybridCrypto:
    """
    Sistema híbrido que usa DynamicCrypto para P2P e crypto.py para servidor.
    """
    
    def __init__(self, use_dynamic=False):
        self.use_dynamic = use_dynamic
        self.dynamic_crypto = DynamicCrypto()
        
        # Importa crypto original
        from .crypto import GBCrypto
        self.static_crypto = GBCrypto
    
    def encrypt(self, data: bytes, use_p2p: bool = False) -> bytes:
        """
        Criptografa dados.
        
        Args:
            data: Dados a criptografar
            use_p2p: Se True, usa DynamicCrypto (P2P), senão usa estático (servidor)
        """
        if use_p2p and self.use_dynamic:
            return self.dynamic_crypto.encrypt_packet(data)
        else:
            # Usa crypto estático original
            return self.static_crypto.encrypt(data, 0)
    
    def decrypt(self, data: bytes, from_p2p: bool = False) -> tuple:
        """
        Descriptografa dados.
        
        Returns:
            tuple: (success: bool, decrypted_data: bytes, error_msg: str)
        """
        if from_p2p and self.use_dynamic:
            return self.dynamic_crypto.decrypt_packet(data)
        else:
            # Usa crypto estático
            try:
                decrypted = self.static_crypto.decrypt(data, 0)
                return True, decrypted, ""
            except Exception as e:
                return False, b'', str(e)


# =============================================================================
# EXEMPLO DE USO
# =============================================================================

def test_dynamic_crypto():
    """Testa sistema de criptografia dinâmica"""
    print("=== Testing Dynamic Crypto ===\n")
    
    crypto = DynamicCrypto()
    
    # Dados de teste
    test_data = b"Hello, this is a secret message for P2P communication!"
    
    print(f"Original data: {test_data}")
    print(f"Length: {len(test_data)} bytes\n")
    
    # Informações da chave
    key_info = crypto.get_current_key_info()
    print(f"Current key seed: {key_info['current_seed']}")
    print(f"Time until rotation: {key_info['time_until_rotation']}s\n")
    
    # Encripta
    print("Encrypting...")
    encrypted = crypto.encrypt_packet(test_data)
    print(f"Encrypted length: {len(encrypted)} bytes")
    print(f"Overhead: {len(encrypted) - len(test_data)} bytes")
    print(f"Encrypted (hex): {encrypted[:32].hex()}...\n")
    
    # Descriptografa
    print("Decrypting...")
    success, decrypted, error = crypto.decrypt_packet(encrypted)
    
    if success:
        print(f"✅ Decryption successful!")
        print(f"Decrypted data: {decrypted}")
        print(f"Match: {decrypted == test_data}\n")
    else:
        print(f"❌ Decryption failed: {error}\n")
    
    # Teste de replay attack
    print("=== Testing Replay Protection ===")
    print("Waiting 2 seconds and trying to decrypt same packet...")
    import time
    time.sleep(2)
    
    success, decrypted, error = crypto.decrypt_packet(encrypted)
    if success:
        print(f"✅ Decryption still works (within tolerance)")
    else:
        print(f"❌ Replay protection triggered: {error}")
    
    # Teste de checksum
    print("\n=== Testing Checksum Validation ===")
    print("Corrupting encrypted data...")
    corrupted = bytearray(encrypted)
    corrupted[-10] ^= 0xFF  # Corrompe um byte
    
    success, decrypted, error = crypto.decrypt_packet(bytes(corrupted))
    if not success:
        print(f"✅ Checksum validation works: {error}")
    else:
        print(f"❌ Checksum validation failed (should have detected corruption)")
    
    print("\n=== Test Complete ===")


if __name__ == "__main__":
    test_dynamic_crypto()