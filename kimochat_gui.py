#!/usr/bin/env python3
"""
KimoChat GUI + Client Module
===========================
Universidad: Global University - Cryptography Course

Este archivo integra:
- Cliente WebSocket SecureClient con cifrado E2E
- Interfaz GUI Tkinter con:
  * Server Log (scrolledtext)
  * Panel Client 1 (log + input + send)
  * Panel Client 2 (log + input + send)

Ejecución:
    python kimochat_gui.py
"""

import asyncio
import json
import queue
import threading
import websockets
from typing import Optional


# Importar módulos del proyecto
import kimochat_crypto


# ============================================================================
# CONFIGURACIÓN GLOBAL
# ============================================================================
SERVER_HOST = "localhost"
SERVER_PORT = 8765

# Colas para comunicación thread-safe (GUI <-> threads asyncio)
queue_to_gui_server = queue.Queue()
queue_to_gui_client1 = queue.Queue()
queue_to_gui_client2 = queue.Queue()

# Colas para envío desde GUI hacia clientes
queue_from_gui_client1 = queue.Queue()
queue_from_gui_client2 = queue.Queue()


# ============================================================================
# CLIENTE WEBSOCKET CON CRIPTOGRAFÍA
# ============================================================================

class SecureClient:
    """
    Cliente WebSocket con cifrado extremo-a-extremo.
    
    Estados:
    - CONNECTED: Conectado al servidor
    - REGISTERED: Registrado con username
    - SECURE READY: Canal seguro establecido
    
    Handshake:
    1. Conectar al servidor WebSocket
    2. Registrarse con username
    3. Intercambiar llaves públicas (ECDH)
    4. Derivar clave Fernet (HKDF)
    5. Listo para chat cifrado
    """
    
    def __init__(self, username: str, target_peer: str, 
                 queue_out: queue.Queue, crypto_handler: kimochat_crypto.CryptoHandler):
        self.username = username
        self.target_peer = target_peer
        self.queue_out = queue_out
        self.crypto = crypto_handler
        self.websocket = None
        self.status = "DISCONNECTED"
        self.is_handshake_complete = False
        self.is_running = False
        
    async def connect(self):
        """Conectar al servidor WebSocket"""
        self.status = "CONNECTING"
        self.websocket = await websockets.connect(
            f"ws://{SERVER_HOST}:{SERVER_PORT}",
            ping_interval=30,
            ping_timeout=10
        )
        self.status = "CONNECTED"
        self.queue_out.put(f"[STATUS] {self.username}: Connected")
        
    async def register(self):
        """Registrarse en el servidor"""
        message = {
            "type": "register",
            "from": self.username,
            "to": None
        }
        await self.websocket.send(json.dumps(message))
        
        # Esperar confirmación
        try:
            response = await asyncio.wait_for(
                self.websocket.recv(),
                timeout=5.0
            )
            data = json.loads(response)
            if data.get("status") == "ok":
                self.status = "REGISTERED"
                self.queue_out.put(f"[STATUS] {self.username}: Registered as {data.get('username')}")
                return True
        except asyncio.TimeoutError:
            self.queue_out.put(f"[ERROR] Timeout en registro")
            return False
            
        return False
    
    async def send_pubkey_offer(self):
        """
        Paso 1/3 del handshake: Enviar oferta de clave pública.
        
        Estructura:
        - type: "pubkey_offer"
        - from: username emisor
        - to: username destinatario
        - public_key_pem: llave pública en PEM (sin cifrar)
        
        NOTA: La llave pública es pública, no necesita cifrado.
        """
        pubkey_pem = self.crypto.generate_keypair()
        
        message = {
            "type": "pubkey_offer",
            "from": self.username,
            "to": self.target_peer,
            "public_key_pem": pubkey_pem.decode("utf-8")
        }
        
        await self.websocket.send(json.dumps(message))
        self.queue_out.put(f"[HANDSHAKE] {self.username}: PubKey Offer enviada a {self.target_peer}")
        
    async def handle_pubkey_offer(self, data: dict):
        """
        Paso 2/3: Manejar oferta recibida.
        
        1. Guardar llave pública del peer
        2. Generar nuestro par de claves
        3. Derivar secreto compartido
        4. Enviar pubkey_accept
        """
        peer_pubkey_pem = data.get("public_key_pem").encode("utf-8")
        print(f"[DEBUG] {self.username}: handle_pubkey_offer called, deriving secret")
        
        # Derivar secreto compartido
        self.crypto.derive_shared_secret(peer_pubkey_pem)
        print(f"[DEBUG] {self.username}: secret derived, generating new keypair")
        
        # Generar nuestra llave y responder
        our_pubkey_pem = self.crypto.generate_keypair()
        print(f"[DEBUG] {self.username}: sending pubkey_accept")
        
        message = {
            "type": "pubkey_accept",
            "from": self.username,
            "to": self.target_peer,
            "public_key_pem": our_pubkey_pem.decode("utf-8")
        }
        
        await self.websocket.send(json.dumps(message))
        self.queue_out.put(f"[HANDSHAKE] {self.username}: PubKey Accept enviada")

    async def handle_pubkey_accept(self, data: dict):
        """
        Paso 3/3: Completar handshake.
        
        1. Derivar secreto compartido
        2. Derivar clave Fernet (HKDF)
        3. Canal seguro listo
        """
        peer_pubkey_pem = data.get("public_key_pem").encode("utf-8")
        print(f"[DEBUG] {self.username}: handle_pubkey_accept called, peer key: {peer_pubkey_pem[:50]}...")
        
        try:
            # Derivar secreto compartido
            self.crypto.derive_shared_secret(peer_pubkey_pem)
            print(f"[DEBUG] {self.username}: shared secret derived")
            
            # Derivar clave Fernet
            self.crypto.derive_fernet_key()
            print(f"[DEBUG] {self.username}: Fernet key derived")
        except Exception as e:
            print(f"[ERROR] {self.username}: Crypto error in handle_pubkey_accept: {e}")
            import traceback
            traceback.print_exc()
            self.queue_out.put(f"[ERROR] {self.username}: {e}")
            return

        self.crypto.channel_ready = True
        self.status = "SECURE READY"
        self.is_handshake_complete = True

        self.queue_out.put(f"[STATUS] {self.username}: Secure channel ready!")
        print(f"[DEBUG] {self.username}: channel_ready = True")

    async def initiate_handshake(self):
        """
        Iniciar handshake con el peer.
        
        Retry logic: reintentar cada 2 segundos si el peer no responde.
        """
        max_retries = 10
        retry_count = 0
        
        while not self.is_handshake_complete and retry_count < max_retries:
            await self.send_pubkey_offer()
            
            try:
                response = await asyncio.wait_for(
                    self.websocket.recv(),
                    timeout=3.0
                )
                data = json.loads(response)
                
                if data.get("type") == "pubkey_accept":
                    await self.handle_pubkey_accept(data)
                    break
                    
            except asyncio.TimeoutError:
                retry_count += 1
                self.queue_out.put(f"[HANDSHAKE] {self.username}: Reintentando... ({retry_count}/{max_retries})")
                await asyncio.sleep(2)
                
        if not self.is_handshake_complete:
            self.queue_out.put(f"[ERROR] {self.username}: Handshake falló")
    
    async def send_message(self, plaintext: str):
        """
        Enviar mensaje cifrado.
        
        Cifrado: plaintext → Fernet → ciphertext → Base64
        """
        if not self.crypto.channel_ready:
            self.queue_out.put(f"[ERROR] Canal seguro no establecido")
            return False
            
        # Cifrar mensaje
        payload_b64 = self.crypto.encrypt_message(plaintext)
        
        message = {
            "type": "chat",
            "from": self.username,
            "to": self.target_peer,
            "payload_b64": payload_b64
        }
        
        await self.websocket.send(json.dumps(message))
        self.queue_out.put(f"[me] {plaintext}")
        
        return True
    
    async def receive_messages(self):
        """
        Recibir mensajes del servidor.
        
        Maneja:
        - chat: descifrar con Fernet
        - pubkey_offer: iniciar respuesta de handshake
        - pubkey_accept: completar handshake
        """
        try:
            async for raw_message in self.websocket:
                try:
                    data = json.loads(raw_message)
                except json.JSONDecodeError as e:
                    self.queue_out.put(f"[ERROR] JSON decode: {e}")
                    continue
                    
                msg_type = data.get("type")
                print(f"[DEBUG] {self.username} received: {msg_type}")
                
                if msg_type == "chat":
                    # ======================================================
                    # DESCIFRADO: Solo el cliente puede descifrar
                    # El servidor solo reenvía payload_b64 sin tocarlo
                    # ======================================================
                    if self.crypto.channel_ready:
                        payload_b64 = data.get("payload_b64")
                        plaintext = self.crypto.decrypt_message(payload_b64)
                        sender = data.get("from")
                        self.queue_out.put(f"[{sender}] {plaintext}")
                    else:
                        self.queue_out.put(f"[WARN] Mensaje sin canal seguro")
                        
                elif msg_type == "pubkey_offer":
                    await self.handle_pubkey_offer(data)
                    
                elif msg_type == "pubkey_accept":
                    await self.handle_pubkey_accept(data)
                    
                elif msg_type == "list":
                    users = data.get("users", [])
                    self.queue_out.put(f"[USERS] {users}")
                    
        except websockets.exceptions.ConnectionClosed:
            self.queue_out.put(f"[STATUS] Conexión cerrada")
            self.is_running = False
    
    async def run(self):
        """Ejecutar cliente"""
        try:
            await self.connect()
            registered = await self.register()
            if not registered:
                return
            
            if self.target_peer:
                await self.send_pubkey_offer()
            
            self.is_running = True
            self.queue_out.put(f"[STATUS] {self.username}: Running, waiting for messages")
            
            target_queue = queue_from_gui_client1 if self.username == "Client1" else queue_from_gui_client2
            
            while self.is_running:
                try:
                    try:
                        msg = target_queue.get_nowait()
                        if msg:
                            await self.send_message(msg)
                    except queue.Empty:
                        pass
                    
                    try:
                        raw_message = await asyncio.wait_for(
                            self.websocket.recv(),
                            timeout=0.1
                        )
                        
                        try:
                            data = json.loads(raw_message)
                        except json.JSONDecodeError as e:
                            self.queue_out.put(f"[ERROR] JSON decode: {e}")
                            continue
                            
                        msg_type = data.get("type")
                        print(f"[DEBUG] {self.username} received: {msg_type}")
                        
                        if msg_type == "chat":
                            if self.crypto.channel_ready:
                                payload_b64 = data.get("payload_b64")
                                plaintext = self.crypto.decrypt_message(payload_b64)
                                sender = data.get("from")
                                self.queue_out.put(f"[{sender}] {plaintext}")
                            else:
                                self.queue_out.put(f"[WARN] Mensaje sin canal seguro")
                                
                        elif msg_type == "pubkey_offer":
                            await self.handle_pubkey_offer(data)
                            
                        elif msg_type == "pubkey_accept":
                            print(f"[DEBUG] {self.username}: Calling handle_pubkey_accept")
                            await self.handle_pubkey_accept(data)
                            
                        elif msg_type == "list":
                            users = data.get("users", [])
                            self.queue_out.put(f"[USERS] {users}")
                            
                    except asyncio.TimeoutError:
                        pass
                    except websockets.exceptions.ConnectionClosed:
                        self.queue_out.put(f"[STATUS] Conexión cerrada")
                        self.is_running = False
                        break
                        
                except Exception as e:
                    print(f"[ERROR] Cliente {self.username}: {e}")
                    break
                    
        except Exception as e:
            self.queue_out.put(f"[ERROR] {self.username}: {e}")
        
    def start_async(self):
        """Iniciar cliente en thread separada"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.run())


# ============================================================================
# GUI TKINTER
# ============================================================================

import tkinter as tk
from tkinter import ttk, scrolledtext


class KimoChatGUI:
    """
    Interfaz gráfica Tkinter.
    
    Layout:
    +--------------------------------------------------+
    |  SERVER LOG (scrolledtext)                       |
    +------------------------+------------------------+
    |  CLIENT 1 PANEL       |  CLIENT 2 PANEL       |
    |  - Status            |  - Status            |
    |  - Log              |  - Log               |
    |  - Input + Send     |  - Input + Send      |
    +------------------------+------------------------+
    |  [Start Server]  [Start Clients]              |
    +--------------------------------------------------+
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("KimoChat - Zero Knowledge Encrypted Chat")
        self.root.geometry("1200x800")
        
        # Referencias
        self.server = None
        self.client1 = None
        self.client2 = None
        self.server_thread = None
        self.client1_thread = None
        self.client2_thread = None
        
        self.create_widgets()
        self.poll_queues()
    
    def create_widgets(self):
        """Crear todos los widgets"""
        
        # ===== SERVER LOG =====
        server_frame = ttk.LabelFrame(self.root, text="Server Log", padding=10)
        server_frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=5)
        
        self.server_log = scrolledtext.ScrolledText(
            server_frame, height=8, width=100, wrap=tk.WORD, state=tk.DISABLED
        )
        self.server_log.pack(fill=tk.BOTH, expand=True)
        
        # ===== CLIENTS PANEL =====
        clients_frame = ttk.Frame(self.root)
        clients_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # ---- Client 1 ----
        client1_frame = ttk.LabelFrame(clients_frame, text="Client 1", padding=10)
        client1_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(client1_frame, text="Estado:").pack(anchor=tk.W)
        self.client1_status = ttk.Label(client1_frame, text="DISCONNECTED", foreground="red")
        self.client1_status.pack(anchor=tk.W, pady=(0, 10))
        
        self.client1_log = scrolledtext.ScrolledText(
            client1_frame, height=20, wrap=tk.WORD, state=tk.DISABLED
        )
        self.client1_log.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        input_frame = ttk.Frame(client1_frame)
        input_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.client1_input = ttk.Entry(input_frame, width=40)
        self.client1_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.client1_send_btn = ttk.Button(input_frame, text="Send", command=lambda: self.send_message("client1"))
        self.client1_send_btn.pack(side=tk.LEFT)
        
        self.client1_input.bind("<Return>", lambda e: self.send_message("client1"))
        
        # ---- Client 2 ----
        client2_frame = ttk.LabelFrame(clients_frame, text="Client 2", padding=10)
        client2_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(client2_frame, text="Estado:").pack(anchor=tk.W)
        self.client2_status = ttk.Label(client2_frame, text="DISCONNECTED", foreground="red")
        self.client2_status.pack(anchor=tk.W, pady=(0, 10))
        
        self.client2_log = scrolledtext.ScrolledText(
            client2_frame, height=20, wrap=tk.WORD, state=tk.DISABLED
        )
        self.client2_log.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        input_frame = ttk.Frame(client2_frame)
        input_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.client2_input = ttk.Entry(input_frame, width=40)
        self.client2_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.client2_send_btn = ttk.Button(input_frame, text="Send", command=lambda: self.send_message("client2"))
        self.client2_send_btn.pack(side=tk.LEFT)
        
        self.client2_input.bind("<Return>", lambda e: self.send_message("client2"))
        
        # ===== CONTROL BUTTONS =====
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_server_btn = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_server_btn.pack(side=tk.LEFT, padx=5)
        
        self.start_clients_btn = ttk.Button(
            control_frame, text="Start Clients", command=self.start_clients, state=tk.DISABLED
        )
        self.start_clients_btn.pack(side=tk.LEFT, padx=5)
    
    def log_message(self, widget, message):
        """Agregar mensaje a widget de texto"""
        widget.config(state=tk.NORMAL)
        widget.insert(tk.END, message + "\n")
        widget.see(tk.END)
        widget.config(state=tk.DISABLED)
    
    def set_status(self, label, status):
        """Actualizar label de status"""
        label.config(text=status)
        
        if "CONNECTED" in status or "Ready" in status:
            label.config(foreground="green")
        elif "DISCONNECTED" in status:
            label.config(foreground="red")
        else:
            label.config(foreground="orange")
    
    def send_message(self, client):
        """Enviar mensaje desde GUI"""
        if client == "client1":
            msg = self.client1_input.get().strip()
            if msg:
                queue_from_gui_client1.put(msg)
                self.client1_input.delete(0, tk.END)
        else:
            msg = self.client2_input.get().strip()
            if msg:
                queue_from_gui_client2.put(msg)
                self.client2_input.delete(0, tk.END)
    
    def poll_queues(self):
        """Polling de colas para actualizar GUI"""
        try:
            while True:
                msg = queue_to_gui_server.get_nowait()
                self.log_message(self.server_log, msg)
        except queue.Empty:
            pass
        
        try:
            while True:
                msg = queue_to_gui_client1.get_nowait()
                self.log_message(self.client1_log, msg)
                if "[STATUS]" in msg:
                    self.set_status(self.client1_status, msg)
        except queue.Empty:
            pass
        
        try:
            while True:
                msg = queue_to_gui_client2.get_nowait()
                self.log_message(self.client2_log, msg)
                if "[STATUS]" in msg:
                    self.set_status(self.client2_status, msg)
        except queue.Empty:
            pass
        
        self.root.after(100, self.poll_queues)
    
    def start_server(self):
        """Iniciar servidor"""
        import kimochat_server
        
        self.start_server_btn.config(state=tk.DISABLED)
        
        def run_server():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(kimochat_server.ZeroKnowledgeServer(SERVER_HOST, SERVER_PORT).start_server())
            queue_to_gui_server.put(f"[SERVER] Servidor iniciado en ws://{SERVER_HOST}:{SERVER_PORT}")
            loop.run_forever()
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        self.root.after(1000, lambda: self.start_clients_btn.config(state=tk.NORMAL))
    
    def start_clients(self):
        """Iniciar clientes"""
        self.start_clients_btn.config(state=tk.DISABLED)
        
        crypto1 = kimochat_crypto.CryptoHandler("Client1")
        crypto2 = kimochat_crypto.CryptoHandler("Client2")
        
        self.client1 = SecureClient(
            username="Client1",
            target_peer="Client2",
            queue_out=queue_to_gui_client1,
            crypto_handler=crypto1
        )
        
        self.client2 = SecureClient(
            username="Client2",
            target_peer="Client1",
            queue_out=queue_to_gui_client2,
            crypto_handler=crypto2
        )
        
        self.client1_thread = threading.Thread(target=self.client1.start_async, daemon=True)
        self.client1_thread.start()
        
        self.client2_thread = threading.Thread(target=self.client2.start_async, daemon=True)
        self.client2_thread.start()
        
        self.log_message(self.server_log, "[GUI] Clientes iniciados")


def main():
    """Punto de entrada"""
    print("=" * 60)
    print("KimoChat - Zero Knowledge Encrypted Chat")
    print("Universidad: Global University - Cryptography Course")
    print("=" * 60)
    print()
    print("Instrucciones:")
    print("1. Click 'Start Server' para iniciar el servidor")
    print("2. Click 'Start Clients' para iniciar Client1 y Client2")
    print("3. Espera al handshake automático")
    print("4. Escribe mensajes y presiona Enter para enviar")
    print()
    
    root = tk.Tk()
    app = KimoChatGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()