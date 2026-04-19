#!/usr/bin/env python3
"""
KimoChat Server Module
=====================
Universidad: Global University - Cryptography Course

Servidor WebSocket Zero Knowledge (ciego).

CARACTERÍSTICAS:
- Solo parsea metadatos: type, from, to
- NO toca payload_b64 ni public_key_pem
- Actúa como retransmisor Unicast puro

Estructuras:
- connected_users: Set[str] (usuarios conectados)
- sockets_by_user: Dict[str, WebSocket] (para reenvío)
"""

import json
import websockets
from typing import Set, Dict


class ZeroKnowledgeServer:
    """
    Servidor WebSocket Zero Knowledge.
    
    El servidor es "ciego": no conoce el contenido de los mensajes.
    Solo retransmite los mensajes sin interpretarlos.
    
    Métodos:
    - register_user(): Registrar usuario
    - unregister_user(): Desregistrar usuario
    - forward_unicast(): Reenviar mensaje a destinatario
    - broadcast_user_list(): Enviar lista de usuarios
    - handle_client(): Manejador de conexión de cliente
    """
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.connected_users: Set[str] = set()
        self.sockets_by_user: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.server = None
        self.is_running = False
        
    async def register_user(self, websocket, username: str):
        """Registrar usuario conectado"""
        self.connected_users.add(username)
        self.sockets_by_user[username] = websocket
        print(f"[SERVER] Usuario registrado: {username}")
        print(f"[SERVER] Usuarios activos: {self.connected_users}")
        
    async def unregister_user(self, username: str):
        """Desregistrar usuario"""
        if username in self.connected_users:
            self.connected_users.remove(username)
        if username in self.sockets_by_user:
            del self.sockets_by_user[username]
        print(f"[SERVER] Usuario desregistrado: {username}")
        
    async def forward_unicast(self, from_user: str, to_user: str, message: dict):
        """
        Reenviar mensaje Unicast al destinatario.
        
        IMPORTANTE: El servidor NO toca payload_b64 ni public_key_pem.
        Solo reenvía el mensaje completo tal cual viene.
        """
        if to_user in self.sockets_by_user:
            try:
                target_socket = self.sockets_by_user[to_user]
                await target_socket.send(json.dumps(message))
                print(f"[SERVER] Mensaje reenviado: {from_user} -> {to_user}")
            except Exception as e:
                print(f"[SERVER] Error al reenviar: {e}")
        else:
            print(f"[SERVER] Usuario no encontrado: {to_user}")
            
    async def broadcast_user_list(self, websocket):
        """Enviar lista de usuarios conectados"""
        message = {
            "type": "list",
            "users": list(self.connected_users)
        }
        await websocket.send(json.dumps(message))
        
    async def handle_client(self, websocket):
        """
        Manejador de cliente WebSocket.
        
        Protocolo Zero Knowledge:
        1. Cliente envía "register" con username
        2. Servidor registra y responde OK
        3. Cliente envía: chat, pubkey_offer, pubkey_accept, list
        4. Servidor reenvía SIN inspectar contenido
        """
        username = None
        
        try:
            async for raw_message in websocket:
                # ==============================================================
                # PARSEO ZERO KNOWLEDGE - Solo metadatos
                # ==============================================================
                try:
                    data = json.loads(raw_message)
                except json.JSONDecodeError as e:
                    print(f"[SERVER] JSON decode error: {e}")
                    continue

                # Extraer SOLO campos permitidos (servidor ciego)
                msg_type = data.get("type")
                from_field = data.get("from")
                to_field = data.get("to")
                
                print(f"[SERVER] Received: type={msg_type}, from={from_field}, to={to_field}")
                
                # ==============================================================
                # REGLA CRÍTICA: NO tocar payload_b64 ni public_key_pem
                # ==============================================================
                
                if msg_type == "register":
                    # Registro de usuario
                    username = from_field
                    await self.register_user(websocket, username)
                    
                    # Confirmar registro
                    response = {
                        "type": "register",
                        "status": "ok",
                        "username": username
                    }
                    await websocket.send(json.dumps(response))
                    print(f"[SERVER] Sent register response to {username}")
                    
                elif msg_type == "list":
                    # Solicitar lista de usuarios
                    await self.broadcast_user_list(websocket)
                    
                elif msg_type in ["chat", "pubkey_offer", "pubkey_accept"]:
                    # Reenviar mensaje sin inspectar (Zero Knowledge)
                    if to_field:
                        await self.forward_unicast(from_field, to_field, data)
                    else:
                        print(f"[SERVER] Mensaje sin destinatario: {msg_type}")
                        
                else:
                    print(f"[SERVER] Tipo desconocido: {msg_type}")
                    
        except websockets.exceptions.ConnectionClosed:
            print(f"[SERVER] Conexión cerrada: {username}")
        except Exception as e:
            print(f"[SERVER] Error in handle_client: {e}")
        finally:
            if username:
                await self.unregister_user(username)
                
    async def start_server(self):
        """Iniciar servidor WebSocket"""
        self.is_running = True
        
        self.server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port,
            ping_interval=30,
            ping_timeout=10
        )
        
        print(f"[SERVER] Iniciado en ws://{self.host}:{self.port}")
        
    async def stop_server(self):
        """Detener servidor"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.is_running = False
        print("[SERVER] Detenido")


async def run_server(host: str = "localhost", port: int = 8765):
    """Ejecutar servidor"""
    server = ZeroKnowledgeServer(host, port)
    await server.start_server()
    
    # Mantener servidor corriendo
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        await server.stop_server()


import asyncio

if __name__ == "__main__":
    print("[SERVER] Iniciando servidor...")
    asyncio.run(run_server())