import asyncio
import json
import websockets
import os

HOST = "127.0.0.1"
PORT = 8765

usuarios_conectados = {}

async def manejar_cliente(websocket):
    usuario_actual = None
    try:
        async for mensaje in websocket:
            try:
                datos = json.loads(mensaje)
                tipo = datos.get("type")
                
                print(f"[{tipo}] from {datos.get('from')}")
                
                if tipo == "register":
                    usuario_actual = datos.get("from")
                    usuarios_conectados[usuario_actual] = websocket
                    print(f"[+] {usuario_actual} connected")
                    
                elif tipo == "list":
                    await websocket.send(json.dumps({
                        "type": "list_result",
                        "users": list(usuarios_conectados.keys())
                    }))
                    
                elif tipo in ("pubkey_offer", "pubkey_accept"):
                    destinatario = datos.get("to")
                    if destinatario in usuarios_conectados:
                        await usuarios_conectados[destinatario].send(mensaje)
                        print(f"[>>] Forwarded {tipo} to {destinatario}")
                    else:
                        await websocket.send(json.dumps({
                            "type": "error", 
                            "message": f"User {destinatario} not online"
                        }))
                        
                elif tipo == "chat":
                    destinatario = datos.get("to")
                    if destinatario in usuarios_conectados:
                        await usuarios_conectados[destinatario].send(mensaje)
                        print(f"[MSG] {usuario_actual} -> {destinatario}")
                    else:
                        await websocket.send(json.dumps({
                            "type": "error", 
                            "message": f"User {destinatario} not online"
                        }))
                        
            except json.JSONDecodeError:
                await websocket.send(json.dumps({
                    "type": "error", 
                    "message": "Invalid JSON"
                }))
    except Exception as e:
        print(f"[SERVER] Error: {e}")
    finally:
        if usuario_actual and usuario_actual in usuarios_conectados:
            del usuarios_conectados[usuario_actual]
            print(f"[-] {usuario_actual} disconnected")

async def main():
    print(f"========================================")
    print(f"   CRYPTOCHAT SERVER - Zero Knowledge")
    print(f"========================================")
    print(f"Listening on: ws://{HOST}:{PORT}")
    print(f"Keep-alive: 180 seconds")
    print(f"----------------------------------------")
    
    async with websockets.serve(manejar_cliente, HOST, PORT, ping_interval=180, ping_timeout=30):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())