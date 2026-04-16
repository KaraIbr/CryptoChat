import asyncio
import json
import websockets
from cryptography.hazmat.primitives.ciphers import rsa
from cryptography.hazmat.primitives.ciphers.asymmetric import padding
from cryptography.hazmat.primitives import serialization

SERVER = "ws://localhost:8765"
USERNAME = "Client1"

from cryptography.hazmat.primitives.ciphers import rsa
from cryptography.hazmat.primitives import serialization

async def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def get_public_key_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )

def encrypt_message(message, public_key):
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.PKCS1v15()
    )

def decrypt_message(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    ).decode('utf-8')

async def chat():
    private_key, my_public_key = await generate_keys()
    peer_public_key = None
    
    print(f"Conectando como {USERNAME}...")
    async with websockets.connect(SERVER) as ws:
        register = {"type": "register", "from": USERNAME}
        await ws.send(json.dumps(register))
        print(f"Registrado como {USERNAME}")
        
        await ws.send(json.dumps({"type": "list"}))
        response = json.loads(await ws.recv())
        print(f"Usuarios disponibles: {response.get('users', [])}")
        
        pubkey_pem = get_public_key_pem(my_public_key)
        offer = {"type": "pubkey_offer", "from": USERNAME, "to": "Client2", "public_key_pem": pubkey_pem.decode()}
        await ws.send(json.dumps(offer))
        print("Enviando mi llave pública a Client2...")
        
        try:
            response = await asyncio.wait_for(ws.recv(), timeout=10)
            datos = json.loads(response)
            if datos.get("type") == "pubkey_offer":
                peer_pubkey_pem = datos.get("public_key_pem")
                peer_public_key = serialization.load_pem_public_key(peer_pubkey_pem.encode())
                print("Recibida llave pública de Client2")
            elif datos.get("type") == "chat":
                payload = bytes.fromhex(datos.get("payload", ""))
                decrypted = decrypt_message(payload, private_key)
                print(f"\nClient2: {decrypted}")
        except asyncio.TimeoutError:
            print("Esperando llave de Client2...")
        
        async def send_messages():
            while True:
                msg = input("Mensaje: ")
                if msg.lower() == "salir":
                    break
                if peer_public_key is None:
                    print("No tengo la llave pública de Client2")
                    continue
                
                encrypted = encrypt_message(msg, peer_public_key)
                message = {
                    "type": "chat",
                    "from": USERNAME,
                    "to": "Client2",
                    "payload": encrypted.hex()
                }
                await ws.send(json.dumps(message))
                print(f"Enviado a Client2")
        
        async def receive_messages():
            try:
                async for msg in ws:
                    datos = json.loads(msg)
                    if datos.get("type") == "chat":
                        payload = bytes.fromhex(datos.get("payload", ""))
                        try:
                            decrypted = decrypt_message(payload, private_key)
                            print(f"\nClient2: {decrypted}")
                        except Exception as e:
                            print(f"\nClient2 (no se pudo descifrar): {payload.hex()}")
                    elif datos.get("type") == "pubkey_offer":
                        peer_pubkey_pem = datos.get("public_key_pem")
                        peer_public_key = serialization.load_pem_public_key(peer_pubkey_pem.encode())
                        print("Recibida llave pública de Client2")
            except websockets.exceptions.ConnectionClosed:
                print("Conexión cerrada")
        
        await asyncio.gather(send_messages(), receive_messages())

if __name__ == "__main__":
    asyncio.run(chat())