import asyncio
import json
import websockets
import sys

HOST = "127.0.0.1"
PORT = 8765

usuarios_conectados = {}

async def manejar_cliente(websocket, path):
    usuario_actual = None
    
    try:
        async for mensaje in websocket:
            try:
                datos = json.loads(mensaje)
                tipo = datos.get("type")
                
                print(f"[DEBUG] Received: {tipo} from {datos.get('from')} to {datos.get('to')}")
                sys.stdout.flush()
                
                if tipo == "register":
                    usuario_actual = datos.get("from")
                    usuarios_conectados[usuario_actual] = websocket
                    print(f"[+] {usuario_actual} connected")
                    sys.stdout.flush()
                    
                elif tipo == "list":
                    respuesta = {
                        "type": "list_result",
                        "users": list(usuarios_conectados.keys())
                    }
                    print(f"[DEBUG] Sending user list: {respuesta}")
                    sys.stdout.flush()
                    await websocket.send(json.dumps(respuesta))
                    
                elif tipo in ("pubkey_offer", "pubkey_accept"):
                    destinatario = datos.get("to")
                    print(f"[DEBUG] Forwarding {tipo} to {destinatario}")
                    sys.stdout.flush()
                    if destinatario and destinatario in usuarios_conectados:
                        await usuarios_conectados[destinatario].send(mensaje)
                    else:
                        error = {"type": "error", "message": f"User {destinatario} not found"}
                        try:
                            await websocket.send(json.dumps(error))
                        except:
                            pass
                        
                elif tipo == "chat":
                    destinatario = datos.get("to")
                    print(f"[DEBUG] Forwarding chat to {destinatario}")
                    sys.stdout.flush()
                    if destinatario and destinatario in usuarios_conectados:
                        await usuarios_conectados[destinatario].send(mensaje)
                    else:
                        error = {"type": "error", "message": f"User {destinatario} not found"}
                        try:
                            await websocket.send(json.dumps(error))
                        except:
                            pass
                        
                else:
                    error = {"type": "error", "message": f"Unknown type: {tipo}"}
                    try:
                        await websocket.send(json.dumps(error))
                    except:
                        pass
                    
            except json.JSONDecodeError as e:
                print(f"[ERROR] Invalid JSON: {e}")
                sys.stdout.flush()
                try:
                    await websocket.send(json.dumps({"type": "error", "message": "Invalid JSON"}))
                except:
                    pass
            except Exception as e:
                print(f"[ERROR] Server error: {e}")
                sys.stdout.flush()
                
    except websockets.exceptions.ConnectionClosed:
        print(f"[DEBUG] Connection closed")
        sys.stdout.flush()
        pass
    finally:
        if usuario_actual and usuario_actual in usuarios_conectados:
            del usuarios_conectados[usuario_actual]
            print(f"[-] {usuario_actual} disconnected")
            sys.stdout.flush()

async def main():
    print(f"Zero-Knowledge Server listening on ws://{HOST}:{PORT}")
    sys.stdout.flush()
    async with websockets.serve(manejar_cliente, HOST, PORT):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())