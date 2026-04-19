#!/usr/bin/env python3
"""
KimoChat Crypto Module
=====================
Universidad: Global University - Cryptography Course

Manejador criptográfico para ECDH + HKDF + Fernet.
Este módulo contiene todas las funciones de cifrado.

Flujo criptográfico:
1. ECDH (SECP384R1) → secreto compartido
2. HKDF-SHA256 → 32 bytes derivados
3. Fernet → cifrado simétrico
"""

import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


class CryptoHandler:
    """
    Manejador criptográfico completo.
    
    Métodos:
    - generate_keypair(): Genera par EC (SECP384R1)
    - derive_shared_secret(): Deriva secreto compartido (ECDH)
    - derive_fernet_key(): Deriva clave Fernet (HKDF)
    - encrypt_message(): Cifra con Fernet
    - decrypt_message(): Descifra con Fernet
    """
    
    def __init__(self, username: str):
        self.username = username
        self.private_key = None
        self.public_key_pem = None
        self.peer_public_key = None
        self.fernet_key = None
        self.shared_secret = None
        self.channel_ready = False
        
    def generate_keypair(self):
        """
        Paso 1/5: Generar par de claves ECDH
        Usar SECP384R1 (curva elíptica estándar NIST)
        """
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        
        self.public_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return self.public_key_pem
    
    def derive_shared_secret(self, peer_public_key_pem: bytes):
        """
        Paso 2/5: Derivar secreto compartido con ECDH
        peer_public_key_pem: llave pública del peer en formato PEM
        """
        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
        
        self.shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        return self.shared_secret
    
    def derive_fernet_key(self):
        """
        Paso 3/5: Derivar clave Fernet con HKDF-SHA256
        
        IMPORTANTE: NO usar el secreto crudo directamente.
        HKDF proporciona derivación cryptográfica segura.
        HKDF-SHA256 → 32 bytes exactos → Base64 urlsafe → Fernet
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kimochat-ephemeral-key',
            backend=default_backend()
        )
        
        derived_key = hkdf.derive(self.shared_secret)
        
        fernet_key_b64 = base64.urlsafe_b64encode(derived_key)
        
        self.fernet_key = fernet_key_b64
        
        return self.fernet_key
    
    def encrypt_message(self, plaintext: str) -> str:
        """
        Paso 4/5: Cifrar mensaje con Fernet
        plaintext: mensaje en texto plano
        Returns: ciphertext codificado en Base64
        """
        if not self.fernet_key:
            raise ValueError("Fernet key no definida. Ejecutar handshake primero.")
        
        f = Fernet(self.fernet_key)
        
        ciphertext = f.encrypt(plaintext.encode("utf-8"))
        payload_b64 = base64.b64encode(ciphertext).decode("utf-8")
        
        return payload_b64
    
    def decrypt_message(self, payload_b64: str) -> str:
        """
        Paso 5/5: Descifrar mensaje con Fernet
        payload_b64: ciphertext codificado en Base64
        Returns: plaintext descifrado
        """
        if not self.fernet_key:
            raise ValueError("Fernet key no definida. Ejecutar handshake primero.")
        
        f = Fernet(self.fernet_key)
        
        ciphertext = base64.b64decode(payload_b64.encode("utf-8"))
        plaintext = f.decrypt(ciphertext).decode("utf-8")
        
        return plaintext


def encrypt_message(fernet_key: bytes, plaintext: str) -> str:
    """
    Función auxiliar: cifrar mensaje.
    """
    f = Fernet(fernet_key)
    ciphertext = f.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_message(fernet_key: bytes, payload_b64: str) -> str:
    """
    Función auxiliar: descifrar mensaje.
    """
    f = Fernet(fernet_key)
    ciphertext = base64.b64decode(payload_b64.encode("utf-8"))
    return f.decrypt(ciphertext).decode("utf-8")