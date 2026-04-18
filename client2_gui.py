import tkinter as tk
from tkinter import scrolledtext, messagebox
import asyncio
import json
import base64
import websockets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

SERVER = "ws://127.0.0.1:8765"
USERNAME = "Client2"
PEER = "Client1"
KEEPALIVE_INTERVAL = 180

class CryptoChatGUI:
    def __init__(self, master):
        self.master = master
        self.master.title(f"CryptoChat - {USERNAME}")
        self.master.geometry("500x600")
        
        self.ws = None
        self.connected = False
        self.fernet = None
        self.my_priv = None
        self.my_pub = None
        self.peer_pub = None
        
        self.setup_ui()
        self.connect_to_server()
    
    def setup_ui(self):
        header_frame = tk.Frame(self.master, bg="#2c3e50", pady=10)
        header_frame.pack(fill=tk.X)
        
        tk.Label(header_frame, text="CRYPTOCHAT", font=("Arial", 16, "bold"), 
                 fg="white", bg="#2c3e50").pack()
        tk.Label(header_frame, text=f"User: {USERNAME} | Peer: {PEER}", 
                 font=("Arial", 10), fg="#bdc3c7", bg="#2c3e50").pack()
        
        self.status_label = tk.Label(self.master, text="[DISCONNECTED]", 
                                      font=("Arial", 10), fg="red", bg="#ecf0f1")
        self.status_label.pack(fill=tk.X, pady=5)
        
        self.chat_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, 
                                                     font=("Arial", 11), height=20)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.chat_area.config(state=tk.DISABLED)
        
        input_frame = tk.Frame(self.master)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.msg_entry = tk.Entry(input_frame, font=("Arial", 12))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", self.send_message)
        
        send_btn = tk.Button(input_frame, text="Send", command=self.send_message,
                            bg="#3498db", fg="white", font=("Arial", 10, "bold"))
        send_btn.pack(side=tk.RIGHT)
        
        btn_frame = tk.Frame(self.master)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Button(btn_frame, text="Salir", command=self.disconnect,
                  bg="#e74c3c", fg="white").pack(side=tk.RIGHT)
    
    def log(self, message, msg_type="info"):
        self.chat_area.config(state=tk.NORMAL)
        prefix = {"info": ">>>", "receive": "<<<", "error": "[ERROR]", "status": "[STATUS]"}.get(msg_type, ">>>")
        self.chat_area.insert(tk.END, f"{prefix} {message}\n")
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)
    
    def update_status(self, status, color="red"):
        self.status_label.config(text=f"[{status}]", fg=color)
    
    def generate_ecdh_keys(self):
        private_key = ec.generate_private_key(ec.SECP384R1())
        return private_key, private_key.public_key()
    
    def public_key_to_pem(self, public_key) -> str:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")
    
    def pem_to_public_key(self, pem_str: str):
        return serialization.load_pem_public_key(pem_str.encode("utf-8"))
    
    def derive_fernet_from_ecdh(self, my_private_key, peer_public_key) -> Fernet:
        shared = my_private_key.exchange(ec.ECDH(), peer_public_key)
        derived_32 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"CryptoChat-ECDH-SECP384R1",
        ).derive(shared)
        fernet_key = base64.urlsafe_b64encode(derived_32)
        return Fernet(fernet_key)
    
    def connect_to_server(self):
        self.my_priv, self.my_pub = self.generate_ecdh_keys()
        self.log("Generating ECDH keys...", "status")
        
        asyncio.create_task(self.connect())
    
    async def connect(self):
        try:
            self.ws = await websockets.connect(SERVER)
            self.connected = True
            self.update_status("CONNECTED", "green")
            self.log("Connected to server", "status")
            
            await self.ws.send(json.dumps({"type": "register", "from": USERNAME}))
            self.log("Registered as " + USERNAME, "status")
            
            await asyncio.sleep(0.3)
            await self.ws.send(json.dumps({"type": "list"}))
            response = json.loads(await self.ws.recv())
            self.log(f"Online users: {', '.join(response.get('users', []))}", "status")
            
            asyncio.create_task(self.receive_messages())
            
        except Exception as e:
            self.log(f"Connection failed: {e}", "error")
            self.update_status("CONNECTION FAILED", "red")
    
    async def keepalive(self):
        while self.connected:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if self.connected and self.ws:
                try:
                    await self.ws.ping()
                    self.log("Keepalive ping", "status")
                except:
                    break
    
    async def receive_messages(self):
        try:
            async for raw in self.ws:
                try:
                    data = json.loads(raw)
                    t = data.get("type")
                    
                    if t == "pubkey_offer":
                        self.peer_pub = self.pem_to_public_key(data.get("public_key_pem"))
                        self.fernet = self.derive_fernet_from_ecdh(self.my_priv, self.peer_pub)
                        
                        await self.ws.send(json.dumps({
                            "type": "pubkey_accept",
                            "from": USERNAME,
                            "to": PEER,
                            "public_key_pem": self.public_key_to_pem(self.my_pub),
                        }))
                        self.log("SECURE CHANNEL READY - ECDH Key Exchanged", "status")
                        self.update_status("SECURE CHANNEL", "blue")
                        asyncio.create_task(self.keepalive())
                        
                    elif t == "pubkey_accept":
                        self.peer_pub = self.pem_to_public_key(data.get("public_key_pem"))
                        self.fernet = self.derive_fernet_from_ecdh(self.my_priv, self.peer_pub)
                        self.log("SECURE CHANNEL READY - ECDH Key Exchanged", "status")
                        self.update_status("SECURE CHANNEL", "blue")
                        asyncio.create_task(self.keepalive())
                        
                    elif t == "chat":
                        if not self.fernet:
                            self.log("Received but no secure channel", "error")
                            continue
                        ciphertext = base64.b64decode(data.get("payload_b64", ""))
                        plaintext = self.fernet.decrypt(ciphertext).decode("utf-8")
                        self.log(f"{data.get('from')}: {plaintext}", "receive")
                        
                    elif t == "error":
                        self.log(f"Server error: {data.get('message')}", "error")
                        
                except json.JSONDecodeError:
                    pass
        except websockets.exceptions.ConnectionClosed:
            self.log("Disconnected from server", "error")
            self.update_status("DISCONNECTED", "red")
    
    def send_message(self, event=None):
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        
        if not self.fernet:
            messagebox.showwarning("No Secure Channel", "Waiting for key exchange...")
            return
        
        self.msg_entry.delete(0, tk.END)
        
        ciphertext = self.fernet.encrypt(msg.encode("utf-8"))
        payload_b64 = base64.b64encode(ciphertext).decode("utf-8")
        
        asyncio.create_task(self.ws.send(json.dumps({
            "type": "chat",
            "from": USERNAME,
            "to": PEER,
            "payload_b64": payload_b64,
        })))
        
        self.log(f"{USERNAME}: {msg}", "info")
    
    def disconnect(self):
        if self.connected and self.ws:
            asyncio.create_task(self.ws.close())
        self.master.destroy()

def main():
    root = tk.Tk()
    app = CryptoChatGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()