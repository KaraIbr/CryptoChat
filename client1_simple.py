import asyncio
import json
import base64
import websockets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

SERVER = "ws://127.0.0.1:8765"
USERNAME = "Client1"
PEER = "Client2"
KEEPALIVE_INTERVAL = 180  # 3 minutes

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    return private_key, private_key.public_key()

def public_key_to_pem(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")

def pem_to_public_key(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))

def derive_fernet_from_ecdh(my_private_key, peer_public_key) -> Fernet:
    shared = my_private_key.exchange(ec.ECDH(), peer_public_key)
    derived_32 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"CryptoChat-ECDH-SECP384R1",
    ).derive(shared)
    fernet_key = base64.urlsafe_b64encode(derived_32)
    return Fernet(fernet_key)

def print_header():
    print("=" * 50)
    print("   CRYPTOCHAT - E2E ENCRYPTED MESSENGER")
    print("=" * 50)
    print(f"User: {USERNAME} | Peer: {PEER}")
    print("-" * 50)

def print_status(status):
    print(f"[{status}]")

def print_message(direction, msg):
    arrow = ">>>" if direction == "out" else "<<<"
    print(f"{arrow} {msg}")

async def main():
    my_priv, my_pub = generate_ecdh_keys()
    peer_pub = None
    fernet = None
    ws = None
    connected = False
    
    print_header()
    print_status("CONNECTING")
    
    try:
        ws = await websockets.connect(SERVER)
        connected = True
        print_status("CONNECTED")
        
        await ws.send(json.dumps({"type": "register", "from": USERNAME}))
        print_status("REGISTERED")
        
        await asyncio.sleep(0.3)
        await ws.send(json.dumps({"type": "list"}))
        response = json.loads(await ws.recv())
        print(f"Online users: {', '.join(response.get('users', []))}")
        
        await ws.send(json.dumps({
            "type": "pubkey_offer",
            "from": USERNAME,
            "to": PEER,
            "public_key_pem": public_key_to_pem(my_pub),
        }))
        print_status("PUBLIC KEY SENT")
        
        async def keepalive():
            """Send ping every 3 minutes to keep connection alive"""
            while connected:
                await asyncio.sleep(KEEPALIVE_INTERVAL)
                if connected and ws:
                    try:
                        await ws.ping()
                        print_status("KEEPALIVE PING")
                    except:
                        break
        
        async def receiver():
            nonlocal peer_pub, fernet
            try:
                async for raw in ws:
                    try:
                        data = json.loads(raw)
                        t = data.get("type")
                        
                        if t in ("pubkey_offer", "pubkey_accept"):
                            peer_pub = pem_to_public_key(data.get("public_key_pem"))
                            fernet = derive_fernet_from_ecdh(my_priv, peer_pub)
                            print_status("SECURE CHANNEL READY - ECDH KEY EXCHANGED")
                            print("-" * 50)
                            
                        elif t == "chat":
                            if not fernet:
                                print_status("RECEIVED BUT NO SECURE CHANNEL")
                                continue
                            ciphertext = base64.b64decode(data.get("payload_b64", ""))
                            plaintext = fernet.decrypt(ciphertext).decode("utf-8")
                            print_message("in", plaintext)
                            
                        elif t == "error":
                            print(f"Error: {data.get('message')}")
                            
                    except json.JSONDecodeError:
                        pass
            except websockets.exceptions.ConnectionClosed:
                print_status("DISCONNECTED")
                    
        async def sender():
            while connected:
                await asyncio.sleep(0.2)
                if not connected or not fernet:
                    continue
                try:
                    msg = input("")
                    if not connected:
                        break
                    if msg.lower() == "salir":
                        print_status("DISCONNECTING")
                        break
                    if msg.strip():
                        ciphertext = fernet.encrypt(msg.encode("utf-8"))
                        payload_b64 = base64.b64encode(ciphertext).decode("utf-8")
                        await ws.send(json.dumps({
                            "type": "chat",
                            "from": USERNAME,
                            "to": PEER,
                            "payload_b64": payload_b64,
                        }))
                        print_message("out", msg)
                except (EOFError, KeyboardInterrupt):
                    break
                    
        keepalive_task = asyncio.create_task(keepalive())
        
        try:
            await asyncio.gather(receiver(), sender())
        finally:
            keepalive_task.cancel()
            connected = False
            if ws:
                await ws.close()
                
    except ConnectionRefusedError:
        print_status("CONNECTION REFUSED - Is server running?")
    except Exception as e:
        print_status(f"ERROR: {e}")
    finally:
        print_status("SESSION ENDED")

if __name__ == "__main__":
    asyncio.run(main())