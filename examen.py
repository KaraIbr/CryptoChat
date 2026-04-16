from cryptography.hazmat.primitives.ciphers import rsa
from cryptography.hazmat.primitives import serialization


llave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
llave_publica = llave_privada.public_key()

with open("mi_llave_privada.pem", "wb") as f:
    f.write(llave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("mi_llave_publica.pem", "wb") as f:
    f.write(llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    ))

