
from Crypto.Cipher import AES
import binascii

# CHAVES DE CRIPTOGRAFIA (AES-128 ECB)
# Baseadas no código Rust fornecido pelo usuário.
# OBS: O código Rust usa hex::decode, então as chaves devem ser convertidas de Hex para Bytes.

# CHAVES DE CRIPTOGRAFIA (AES-128 ECB)
# Baseadas no código Java (GunBound-Java-main)
# A chave estática "FFB3B3...EB0" é chamada de FIXED_KEY e usada para decriptar pacotes estáticos.
# O código Java não diferencia Launcher/Broker explicitamente com chaves diferentes no staticCipher, 
# mas usa a mesma FIXED_KEY. Vamos atualizar para usar essa chave confirmada.

# KEY_STATIC_HEX = "FFB3B3BEAE97AD83B9610E23A43C2EB0" # GameServer Key (Failed)
KEY_STATIC_HEX = "A92753041BFCACE65B2338346846038C" # Broker Key (Trying this)

# Mantendo as antigas como backup comentado caso a versão do client varie
# KEY_LAUNCHER_HEX = "FAAA85AA40AAAAAAAAAAAA7AAAAAAAAA"
# KEY_BROKER_HEX = "AAAAA5AA41BFCAAAAAAAAAA3AA84AA3A"

class GBCrypto:
    @staticmethod
    def decrypt(data: bytes, key_type: int) -> bytes:
        """
        Descriptografa um bloco de dados usando AES-128-ECB.
        :param data: Bytes criptografados.
        :param key_type: (Ignorado agora, usa FIXED_KEY única do Java)
        :return: Bytes descriptografados.
        """
        try:
            # Usando a chave única encontrada no emulador Java
            key = binascii.unhexlify(KEY_STATIC_HEX)
            
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(data)
            return decrypted
        except Exception as e:
            print(f"Decryption Error: {e}")
            return data 

    @staticmethod
    def encrypt(data: bytes, key_type: int) -> bytes:
        """
        Criptografa dados usando AES-128-ECB.
        """
        try:
            key = binascii.unhexlify(KEY_STATIC_HEX)
            
            cipher = AES.new(key, AES.MODE_ECB)
            
            pad_len = 16 - (len(data) % 16)
            if pad_len != 16:
                data += b'\0' * pad_len
                
            encrypted = cipher.encrypt(data)
            return encrypted
        except Exception as e:
            print(f"Encryption Error: {e}")
            return data
