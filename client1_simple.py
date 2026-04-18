import asyncio
import json
import base64
import websockets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

SERVER = "ws://localhost:8765"
USERNAME = "Client1"
PEER = "Client2"

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

async def main():
    my_priv, my_pub = generate_ecdh_keys()
    peer_pub = None
    fernet = None
    
    print(f"Connecting as {USERNAME}...")
    
    try:
        async with websockets.connect(SERVER) as ws:
            await ws.send(json.dumps({"type": "register", "from": USERNAME}))
            print("Registered")
            
            await asyncio.sleep(0.3)
            await ws.send(json.dumps({"type": "list"}))
            response = json.loads(await ws.recv())
            print(f"Users: {response.get('users', [])}")
            
            await ws.send(json.dumps({
                "type": "pubkey_offer",
                "from": USERNAME,
                "to": PEER,
                "public_key_pem": public_key_to_pem(my_pub),
            }))
            print(f"Sent public key to {PEER}")
            
            async for raw in ws:
                try:
                    data = json.loads(raw)
                    t = data.get("type")
                    print(f"Received: {t}")
                    
                    if t in ("pubkey_offer", "pubkey_accept"):
                        peer_pub = pem_to_public_key(data.get("public_key_pem"))
                        fernet = derive_fernet_from_ecdh(my_priv, peer_pub)
                        print("Secure channel ready!")
                        
                    elif t == "chat":
                        if not fernet:
                            print("No secure channel yet")
                            continue
                        ciphertext = base64.b64decode(data.get("payload_b64", ""))
                        plaintext = fernet.decrypt(ciphertext).decode("utf-8")
                        print(f"[peer] {plaintext}")
                        
                    elif t == "error":
                        print(f"Error: {data.get('message')}")
                        
                except json.JSONDecodeError:
                    pass
                    
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")

if __name__ == "__main__":
    asyncio.run(main())