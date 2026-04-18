"""
client2.py - E2E Encrypted Client using ECDH + Fernet

Cryptography:
- Key exchange: ECDH with SECP384R1 curve (ephemeral keys per session)
- Key derivation: HKDF-SHA256 -> 32 bytes -> base64.urlsafe_b64encode
- Encryption: Fernet (symmetric AES-128-CBC with HMAC)
- Payload format: base64 encoded ciphertext in JSON field "payload_b64"

Zero-Knowledge Server:
- Server only routes JSON envelopes (type/from/to)
- Server never sees plaintext, private keys, or derived symmetric keys
"""

import asyncio
import json
import base64
import websockets
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

SERVER = "ws://localhost:8765"
USERNAME = "Client2"
PEER = "Client1"


def generate_ecdh_keys():
    """Generate ephemeral EC keypair (SECP384R1) - NO hardcoded keys, NO disk writes"""
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
    """
    Derive Fernet key from ECDH shared secret using HKDF.
    NEVER use raw shared secret - always derive via HKDF-SHA256.
    """
    shared = my_private_key.exchange(ec.ECDH(), peer_public_key)

    derived_32 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"CryptoChat-ECDH-SECP384R1",
    ).derive(shared)

    fernet_key = base64.urlsafe_b64encode(derived_32)
    return Fernet(fernet_key)


async def chat():
    my_priv, my_pub = generate_ecdh_keys()
    peer_pub = None
    fernet = None

    print(f"Connecting as {USERNAME}...")
    try:
        async with websockets.connect(SERVER) as ws:
            await ws.send(json.dumps({"type": "register", "from": USERNAME}))
            print("Registered.")
            sys.stdout.flush()

            await asyncio.sleep(0.5)
            
            await ws.send(json.dumps({"type": "list"}))
            response = json.loads(await ws.recv())
            print(f"Available users: {response.get('users', [])}")
            sys.stdout.flush()

            async def receive_loop():
                nonlocal peer_pub, fernet
                try:
                    async for raw in ws:
                        try:
                            data = json.loads(raw)
                            t = data.get("type")
                            print(f"[DEBUG] Received: {t}")
                            sys.stdout.flush()

                            if t == "pubkey_offer":
                                pem = data.get("public_key_pem")
                                if pem:
                                    peer_pub = pem_to_public_key(pem)
                                    fernet = derive_fernet_from_ecdh(my_priv, peer_pub)

                                    await ws.send(json.dumps({
                                        "type": "pubkey_accept",
                                        "from": USERNAME,
                                        "to": PEER,
                                        "public_key_pem": public_key_to_pem(my_pub),
                                    }))
                                    print("[OK] Public key received and sent mine. Secure channel ready.")
                                    sys.stdout.flush()
                            elif t == "pubkey_accept":
                                pem = data.get("public_key_pem")
                                if pem:
                                    peer_pub = pem_to_public_key(pem)
                                    fernet = derive_fernet_from_ecdh(my_priv, peer_pub)
                                    print("[OK] Public key accept received. Secure channel ready.")
                                    sys.stdout.flush()
                            elif t == "chat":
                                payload_b64 = data.get("payload_b64", "")
                                if not fernet:
                                    print("[WARN] Message received but no secure channel yet.")
                                    sys.stdout.flush()
                                    continue
                                try:
                                    ciphertext = base64.b64decode(payload_b64.encode("utf-8"))
                                    plaintext = fernet.decrypt(ciphertext).decode("utf-8")
                                    print(f"\n[peer] {plaintext}")
                                    sys.stdout.flush()
                                except Exception as e:
                                    print(f"[ERROR] Could not decrypt: {e}")
                                    sys.stdout.flush()
                            elif t == "error":
                                print(f"[SERVER ERROR] {data.get('message')}")
                                sys.stdout.flush()
                            elif t == "list_result":
                                pass
                            else:
                                print(f"[INFO] Unknown message: {data}")
                                sys.stdout.flush()
                        except json.JSONDecodeError as e:
                            print(f"[ERROR] Invalid JSON: {e}")
                            sys.stdout.flush()
                except websockets.exceptions.ConnectionClosed:
                    print("[INFO] Disconnected from server")
                    sys.stdout.flush()

            async def send_loop():
                nonlocal fernet
                while True:
                    try:
                        msg = input("Message (type 'salir' to quit): ").strip()
                        if msg.lower() == "salir":
                            break
                        print(f"[me] {msg}")
                        sys.stdout.flush()
                        if not fernet:
                            print("No secure channel yet (waiting for ECDH/pubkey).")
                            sys.stdout.flush()
                            continue

                        ciphertext = fernet.encrypt(msg.encode("utf-8"))
                        payload_b64 = base64.b64encode(ciphertext).decode("utf-8")

                        await ws.send(json.dumps({
                            "type": "chat",
                            "from": USERNAME,
                            "to": PEER,
                            "payload_b64": payload_b64,
                        }))
                    except EOFError:
                        break
                    except Exception as e:
                        print(f"[ERROR] {e}")
                        sys.stdout.flush()
                        break

            await asyncio.gather(receive_loop(), send_loop())
    except websockets.exceptions.InvalidURI:
        print(f"[ERROR] Invalid server URL: {SERVER}")
        sys.stdout.flush()
    except ConnectionRefusedError:
        print("[ERROR] Connection refused. Is the server running?")
        sys.stdout.flush()
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(chat())