"""
server.py - Zero-Knowledge Relay Server (Blind Router)

PROTOCOL (Zero-Knowledge):
- Server reads ONLY JSON headers: type, from, to
- Server NEVER decrypts payloads, manages keys, or modifies encrypted data
- Public keys forwarded as opaque PEM strings
- Encrypted payloads forwarded as opaque base64 strings

Message types (server handles):
- register: {"type": "register", "from": "username"}
- list: {"type": "list"} -> returns {"type": "list_result", "users": [...]}
- pubkey_offer / pubkey_accept: {"type": "pubkey_*", "from": "", "to": "", "public_key_pem": "PEM..."}
- chat: {"type": "chat", "from": "", "to": "", "payload_b64": "base64..."}
"""

import asyncio
import json
import websockets

HOST = "0.0.0.0"
PORT = 8765

# users: username -> websocket
usuarios_conectados = {}

async def manejar_cliente(websocket, path):
    """
    Maneja conexión de cliente
    El servidor NO conoce el contenido del payload - solo enruta
    """
    usuario_actual = None
    
    try:
        async for mensaje in websocket:
            try:
                datos = json.loads(mensaje)
                tipo = datos.get("type")
                
                # Solo leemoscabecera JSON para enrutar
                # El resto (payload, public_key_pem) se reenvía intacto
                
                if tipo == "register":
                    # Registro: guardar username y asociar WebSocket
                    usuario_actual = datos.get("from")
                    usuarios_conectados[usuario_actual] = websocket
                    print(f"[+] {usuario_actual} conectado")
                    
                elif tipo == "list":
                    # Devolver lista de usuarios conectados
                    respuesta = {
                        "type": "list_result",
                        "users": list(usuarios_conectados.keys())
                    }
                    await websocket.send(json.dumps(respuesta))
                    
                elif tipo in ("pubkey_offer", "pubkey_accept"):
                    # Reenviar llave pública al destinatario (servidor NO la toca)
                    destinatario = datos.get("to")
                    if destinatario and destinatario in usuarios_conectados:
                        await usuarios_conectados[destinatario].send(mensaje)
                    else:
                        # Usuario no encontrado
                        error = {"type": "error", "message": f"Usuario {destinatario} no encontrado"}
                        await websocket.send(json.dumps(error))
                        
                elif tipo == "chat":
                    # Reenviar mensaje cifrado al destinatario (servidor NO lo toca)
                    destinatario = datos.get("to")
                    if destinatario and destinatario in usuarios_conectados:
                        await usuarios_conectados[destinatario].send(mensaje)
                    else:
                        error = {"type": "error", "message": f"Usuario {destinatario} no encontrado"}
                        await websocket.send(json.dumps(error))
                        
                else:
                    error = {"type": "error", "message": f"Tipo desconocido: {tipo}"}
                    await websocket.send(json.dumps(error))
                    
            except json.JSONDecodeError:
                error = {"type": "error", "message": "JSON inválido"}
                await websocket.send(json.dumps(error))
                
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        # Desconectar: eliminar de usuarios
        if usuario_actual and usuario_actual in usuarios_conectados:
            del usuarios_conectados[usuario_actual]
            print(f"[-] {usuario_actual} desconectado")

async def main():
    print(f"Servidor KimoChat escuchando en {HOST}:{PORT}")
    async with websockets.serve(manejar_cliente, HOST, PORT):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())