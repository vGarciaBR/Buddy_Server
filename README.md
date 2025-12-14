# 🎮 GunBound Buddy Server - P2P Hybrid Edition

Um servidor de chat e sistema de amigos (Buddy System) para GunBound World Champion, implementado em Python com suporte a conexões P2P (Peer-to-Peer) e relay híbrido.

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Configuração](#-configuração)
- [Uso](#-uso)
- [Arquitetura](#-arquitetura)
- [Protocolo de Comunicação](#-protocolo-de-comunicação)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Desenvolvimento](#-desenvolvimento)

## 🎯 Visão Geral

O **Buddy Server** é um componente essencial da infraestrutura de servidores privados do GunBound. Ele gerencia:

- Sistema de amigos (Buddy List)
- Chat privado entre jogadores
- Sistema de convites para partidas
- Status de usuários (Online, Ocupado, Jogando, etc.)
- Mensagens offline
- Conexões P2P otimizadas para reduzir latência

Este servidor foi desenvolvido através de engenharia reversa do protocolo original do GunBound, com melhorias modernas como suporte P2P híbrido.

## ✨ Características

### Core Features
- ✅ **Autenticação de Usuários** - Login seguro integrado com banco de dados MySQL
- ✅ **Sistema de Amigos** - Adicionar, remover e organizar amigos em grupos
- ✅ **Chat Privado** - Mensagens em tempo real entre jogadores
- ✅ **Mensagens Offline** - Armazenamento e entrega de mensagens quando o destinatário está offline
- ✅ **Sistema de Convites** - Enviar, aceitar e rejeitar convites para partidas
- ✅ **Gerenciamento de Status** - Estados: Online, Ocupado, Ausente, Jogando, etc.

### Advanced Features
- 🔗 **P2P Híbrido** - Tentativa automática de conexão direta entre clientes, com fallback para relay
- 📊 **Estatísticas em Tempo Real** - Monitoramento de conexões, mensagens e taxa de sucesso P2P
- 🔐 **Criptografia** - Suporte a criptografia de pacotes (GBCrypto)
- 🌐 **Integração com BuddyCenter** - Comunicação com servidor central (opcional)
- 📦 **Tunneling Inteligente** - Roteamento eficiente de pacotes entre usuários
- 🎮 **Integração com GameServer** - Detecção automática de status de jogo

### GUI Features
- 🖥️ **Interface Gráfica** - Painel de controle completo com Tkinter
- 📈 **Monitor ao Vivo** - Visualização em tempo real de métricas do servidor
- 📋 **Logs Detalhados** - Sistema de logging com cores e timestamps
- ⚙️ **Configuração Dinâmica** - Ajuste de parâmetros sem editar código

## 📦 Requisitos

### Sistema
- **Python**: 3.7 ou superior
- **MySQL**: 5.7 ou superior
- **Sistema Operacional**: Windows, Linux ou macOS

### Dependências Python
```
mysql-connector-python
pycryptodome
```

### Banco de Dados
O servidor requer um banco de dados MySQL com as seguintes tabelas:
- `User` - Dados de usuários
- `Game` - Estatísticas de jogo
- `BuddyList` - Lista de amigos
- `CurrentUser` - Status e localização de usuários online
- `LoginLog` - Registro de logins
- `SavePacket` - Armazenamento de mensagens offline

## 🚀 Instalação

### 1. Clone ou baixe o projeto
```bash
cd C:\Users\Eletrocel\.gemini\antigravity\playground\tachyon-glenn
```

### 2. Instale as dependências
```bash
pip install -r requirements.txt
```

### 3. Configure o banco de dados
Execute o script SQL para criar as tabelas necessárias no seu banco de dados MySQL:
```sql
-- Certifique-se de que o banco de dados 'gbwc' existe
CREATE DATABASE IF NOT EXISTS gbwc;
USE gbwc;

-- As tabelas devem seguir o schema do GunBound original
-- (User, Game, BuddyList, CurrentUser, LoginLog, SavePacket)
```

### 4. Configure o servidor
Edite o arquivo `buddy_server/config.py`:
```python
class Config:
    # Server Settings
    HOST = '0.0.0.0'      # IP do servidor
    PORT = 8355           # Porta do Buddy Server
    
    # Database Settings
    DB_HOST = '127.0.0.1'
    DB_USER = 'root'
    DB_PASS = ""
    DB_NAME = "gbwc"
    DB_PORT = 3306
```

## ⚙️ Configuração

### Configuração de Rede
- **HOST**: `0.0.0.0` - Escuta em todas as interfaces de rede
- **PORT**: `8355` - Porta padrão do Buddy Server (pode ser alterada)

### Configuração de Banco de Dados
Ajuste as credenciais do MySQL em `config.py` ou através da interface gráfica.

### Configuração P2P
O sistema P2P é automático e não requer configuração adicional. O servidor:
1. Tenta estabelecer conexão P2P entre clientes
2. Se falhar, usa modo relay (servidor como intermediário)
3. Monitora taxa de sucesso e ajusta automaticamente

## 🎮 Uso

### Iniciar o Servidor (GUI)
```bash
python main.py
```

A interface gráfica será aberta com:
- **Painel de Configuração**: Ajuste IP, porta e credenciais do banco
- **Controles**: Botões para iniciar/parar servidor e visualizar estatísticas
- **Monitor ao Vivo**: Status em tempo real (conexões, usuários, P2P)
- **Logs**: Visualização de pacotes e eventos do servidor

### Iniciar o Servidor (CLI)
Para uso em servidor sem interface gráfica:
```python
from buddy_server.server import BuddyServer
import asyncio

async def main():
    server = BuddyServer(host='0.0.0.0', port=8355)
    await server.start()

if __name__ == "__main__":
    asyncio.run(main())
```

### Comandos da GUI
- **🚀 START SERVER (P2P)**: Inicia o servidor com suporte P2P
- **🛑 STOP SERVER**: Para o servidor graciosamente
- **📊 SHOW STATS**: Exibe estatísticas detalhadas em popup
- **🗑️ Clear Logs**: Limpa a área de logs

## 🏗️ Arquitetura

### Componentes Principais

```
┌─────────────────────────────────────────────────────┐
│                   Main.py (GUI)                     │
│              Interface Gráfica Tkinter              │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│              BuddyServer (server.py)                │
│         Gerenciador Principal do Servidor           │
├─────────────────────────────────────────────────────┤
│  • ClientConnection - Gerencia conexões individuais │
│  • PacketTracer - Rastreamento de pacotes          │
│  • Registro de usuários e sessões                  │
└─────┬───────┬───────┬───────┬───────┬──────────────┘
      │       │       │       │       │
      ▼       ▼       ▼       ▼       ▼
┌─────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐
│Database │ │P2P   │ │Invite│ │Status│ │Tunneling │
│Manager  │ │Mgr   │ │Mgr   │ │Mgr   │ │Manager   │
└─────────┘ └──────┘ └──────┘ └──────┘ └──────────┘
```

### Módulos

#### `server.py`
- **BuddyServer**: Classe principal do servidor
- **ClientConnection**: Gerencia cada conexão de cliente
- **PacketTracer**: Sistema de logging de pacotes

#### `handlers.py`
Processa todos os tipos de pacotes:
- Login e autenticação
- Gerenciamento de amigos (adicionar/remover)
- Chat e mensagens
- Convites de partida
- Atualizações de status
- P2P handshake

#### `database.py`
Interface com MySQL:
- Operações CRUD para usuários e amigos
- Armazenamento de mensagens offline
- Consultas de status e localização
- Logging de atividades

#### `p2p_manager.py`
Sistema P2P híbrido:
- Negociação de conexões P2P
- Fallback para relay
- Estatísticas de sucesso
- Gerenciamento de timeouts

#### `packets.py`
Estruturas de pacotes:
- **Packet**: Classe base para pacotes
- **PacketBuilder**: Construção de pacotes
- **PacketReader**: Leitura de pacotes

#### `crypto.py` / `dynamic_crypto.py`
Criptografia de pacotes compatível com GunBound

#### `user_status.py`
Gerenciamento de estados de usuário:
- Online, Offline, Ocupado, Ausente, Jogando, etc.

#### `invites.py`
Sistema de convites para partidas

#### `tunneling.py`
Roteamento de pacotes entre usuários

## 📡 Protocolo de Comunicação

### Estrutura de Pacotes
```
┌──────────┬──────────┬─────────────────┐
│ Length   │ Opcode   │    Payload      │
│ (2 bytes)│ (2 bytes)│   (N bytes)     │
└──────────┴──────────┴─────────────────┘
```

### Principais Opcodes

#### Autenticação
- `0x1000` - `SVC_LOGIN_REQ` - Requisição de login
- `0x1001` - `SVC_LOGIN_RESP` - Resposta de login
- `0x1010` - `SVC_LOGIN_DATA` - Dados de login

#### Gerenciamento de Amigos
- `0x3000` - `SVC_ADD_BUDDY` - Adicionar amigo
- `0x3001` - `SVC_ADD_BUDDY_RESP` - Resposta
- `0x3002` - `SVC_REMOVE_BUDDY` - Remover amigo
- `0x3003` - `SVC_REMOVE_BUDDY_RESP` - Resposta
- `0x3004` - `SVC_GROUP_BUDDY` - Mover para grupo
- `0x3006` - `SVC_RENAME_GROUP` - Renomear grupo

#### Status e Sincronização
- `0x3010` - `SVC_USER_STATE` - Atualização de status
- `0x3FFF` - `SVC_USER_SYNC` - Sincronização de usuários

#### Mensagens
- `0x2000` - `SVC_SAVE_PACKET` - Salvar mensagem offline
- `0x2011` - `SVC_DELETE_PACKET` - Deletar mensagem
- `0x2020` - `SVC_TUNNEL_PACKET` - Tunelamento de pacote

#### Busca
- `0x4000` - `SVC_SEARCH` - Buscar usuário
- `0x4001` - `SVC_SEARCH_RESP` - Resultado da busca

## 📁 Estrutura do Projeto

```
buddy_server/
├── __init__.py              # Inicialização do módulo
├── server.py                # Servidor principal
├── config.py                # Configurações
├── constants.py             # Constantes (opcodes)
├── packets.py               # Estruturas de pacotes
├── handlers.py              # Handlers de pacotes
├── database.py              # Interface com MySQL
├── crypto.py                # Criptografia básica
├── dynamic_crypto.py        # Criptografia avançada
├── p2p_manager.py           # Sistema P2P
├── user_status.py           # Gerenciamento de status
├── invites.py               # Sistema de convites
├── tunneling.py             # Roteamento de pacotes
├── center_client.py         # Cliente para BuddyCenter
├── hybrid_messaging.py      # Sistema de mensagens híbrido
│
├── analyze_bin.py           # Ferramentas de análise
├── check_offline.py         # Verificação de mensagens offline
├── check_users.py           # Verificação de usuários
├── debug_db.py              # Debug do banco de dados
├── sniffer.py               # Sniffer de pacotes
├── test_*.py                # Testes diversos
│
└── 3 - SERVIDOR/            # Executáveis originais do GunBound
    ├── BuddyCenter2.exe
    ├── BuddyServ2.exe
    ├── GunBoundBroker3.exe
    └── Gunboundserv3.exe
```

## 🛠️ Desenvolvimento

### Ferramentas de Debug

#### Sniffer de Pacotes
```bash
python -m buddy_server.sniffer
```
Captura e analisa pacotes entre cliente e servidor.

#### Verificar Mensagens Offline
```bash
python -m buddy_server.check_offline
```

#### Debug do Banco de Dados
```bash
python -m buddy_server.debug_db
```

#### Análise de Binários
```bash
python -m buddy_server.analyze_bin
```

### Adicionar Novos Handlers

1. Defina o opcode em `constants.py`:
```python
SVC_NEW_FEATURE = 0x5000
```

2. Crie o handler em `handlers.py`:
```python
def handle_new_feature(client, reader):
    # Processar pacote
    data = reader.read_string()
    
    # Responder
    response = PacketBuilder(SVC_NEW_FEATURE_RESP)
    response.write_string("OK")
    client.send_packet(response.build())
```

3. Registre no dispatcher em `handle_packet()`:
```python
elif packet_id == SVC_NEW_FEATURE:
    handle_new_feature(client, reader)
```

### Testes

Execute os testes unitários:
```bash
python -m buddy_server.test_p2p_full
python -m buddy_server.test_save
```

## 📊 Monitoramento e Estatísticas

O servidor fornece estatísticas detalhadas:

### Métricas do Servidor
- Usuários online
- Total de conexões ativas
- Estado do banco de dados
- Link com BuddyCenter

### Métricas P2P
- Tentativas de P2P
- Conexões bem-sucedidas
- Taxa de sucesso (%)
- Conexões P2P ativas
- Conexões em modo relay

### Métricas de Mensagens
- Total de mensagens tuneladas
- Mensagens bem-sucedidas
- Mensagens salvas offline
- Taxa de entrega

### Métricas de Convites
- Convites enviados
- Convites aceitos/rejeitados
- Convites ativos

## 🔒 Segurança

- ✅ Validação de entrada em todos os handlers
- ✅ Proteção contra SQL injection (prepared statements)
- ✅ Criptografia de pacotes (opcional)
- ✅ Timeout de conexões inativas
- ✅ Limitação de taxa (rate limiting) - em desenvolvimento

## 🐛 Troubleshooting

### Servidor não inicia
- Verifique se a porta 8355 está disponível
- Confirme as credenciais do MySQL
- Verifique os logs para erros de conexão

### Clientes não conectam
- Verifique firewall e portas abertas
- Confirme que o IP está correto no cliente
- Verifique se o banco de dados está acessível

### P2P não funciona
- P2P pode falhar devido a NAT/firewall
- O servidor automaticamente usa relay como fallback
- Verifique logs para detalhes de falhas P2P

### Mensagens offline não entregam
- Verifique a tabela `SavePacket` no banco
- Execute `check_offline.py` para diagnóstico
- Confirme que o destinatário está online

## 📝 Licença

Este projeto é para fins educacionais e de pesquisa. GunBound é propriedade da Softnyx.

## 👥 Contribuindo

Contribuições são bem-vindas! Por favor:
1. Faça fork do projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📧 Suporte

Para questões e suporte, abra uma issue no repositório do projeto.

---

**Desenvolvido com ❤️ para a comunidade GunBound**
