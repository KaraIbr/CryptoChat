# KimoChat – Zero Knowledge Encrypted Chat

## Descripción general

KimoChat es un sistema de mensajería con cifrado de extremo a extremo (E2E) diseñado como proyecto académico para un curso de criptografía. Su objetivo es demostrar cómo dos clientes pueden comunicarse de forma segura sin que el servidor tenga acceso al contenido de los mensajes.

El sistema implementa un modelo Zero Knowledge, donde el servidor actúa únicamente como intermediario (relay) y toda la lógica criptográfica ocurre en los clientes.

## Arquitectura del sistema

El proyecto está dividido en tres módulos principales.

### Cliente + GUI (`kimochat_gui.py`)

Este módulo contiene la clase `SecureClient`, que gestiona la lógica de red, y la clase `KimoChatGUI`, que proporciona la interfaz gráfica. También integra colas (`queue`) para comunicación entre la GUI y los clientes, y utiliza `threading` junto con `asyncio` para ejecución concurrente.

Sus responsabilidades incluyen conectarse al servidor (`connect()`), registrarse (`register()`), ejecutar el handshake criptográfico, enviar y recibir mensajes, y mostrar el estado y los logs en la interfaz.

### Servidor Zero Knowledge (`kimochat_server.py`)

Este módulo implementa la clase `ZeroKnowledgeServer`. Su función principal es manejar conexiones y reenviar mensajes entre clientes.

Utiliza métodos como `register_user()` y `unregister_user()` para gestionar usuarios, `handle_client()` para procesar conexiones y `forward_unicast()` para reenviar mensajes.

El servidor no descifra mensajes, no almacena claves y no inspecciona el contenido. Solo procesa metadatos como `type`, `from` y `to`.

### Módulo criptográfico (`kimochat_crypto.py`)

Este componente contiene la clase `CryptoHandler`, que encapsula toda la lógica criptográfica.

Incluye funciones para generar pares de claves (`generate_keypair()`), derivar secretos compartidos (`derive_shared_secret()`), generar claves simétricas (`derive_fernet_key()`), cifrar (`encrypt_message()`) y descifrar (`decrypt_message()`).

## Flujo completo del sistema

El sistema inicia levantando el servidor mediante `start_server()`. Posteriormente, se crean dos clientes que se ejecutan en hilos independientes mediante `start_async()`.

Cada cliente se conecta al servidor usando `connect()` y luego se registra con `register()`. El servidor procesa este registro en `handle_client()` y almacena la conexión mediante `register_user()`. Esto permite mapear usuarios a sockets para reenviar mensajes.

Una vez registrados, los clientes establecen un canal seguro mediante un handshake. Primero, un cliente envía su clave pública usando `send_pubkey_offer()`, la cual fue generada con `generate_keypair()`. El cliente receptor maneja este evento en `handle_pubkey_offer()`, donde deriva un secreto compartido mediante `derive_shared_secret()` y responde con su propia clave pública. Finalmente, el cliente original recibe esta respuesta en `handle_pubkey_accept()`, deriva nuevamente el secreto y genera una clave simétrica mediante `derive_fernet_key()`.

En este punto, ambos clientes poseen la misma clave sin haberla transmitido directamente.

Cuando el usuario envía un mensaje desde la GUI, este se coloca en una cola y es procesado por el cliente en su loop principal (`run()`). El mensaje se cifra mediante `encrypt_message()`, generando un `payload_b64`. Este payload es enviado al servidor, que lo reenvía mediante `forward_unicast()` sin modificarlo.

El cliente receptor recibe el mensaje, lo procesa en `receive_messages()` y lo descifra mediante `decrypt_message()`, mostrando el texto original en la interfaz.

## Modelo Zero Knowledge

El servidor está diseñado bajo una restricción crítica: nunca accede a los datos sensibles. No inspecciona `payload_b64`, no manipula `public_key_pem` y no posee claves criptográficas.

Esto garantiza que el servidor no puede leer ni reconstruir mensajes, incluso si es comprometido.

## Concurrencia

El sistema utiliza una combinación de programación asíncrona y multihilo. `asyncio` maneja la comunicación de red, mientras que `threading` permite ejecutar múltiples clientes en paralelo sin bloquear la interfaz gráfica.

Las colas (`queue`) actúan como mecanismo de sincronización entre la GUI y los clientes, evitando condiciones de carrera.

## Seguridad

El sistema implementa un esquema de cifrado híbrido. Utiliza ECDH para intercambio de claves, HKDF con SHA-256 para derivación segura y Fernet para cifrado simétrico autenticado.

Esto proporciona confidencialidad e integridad de los mensajes. Sin embargo, no incluye autenticación de identidad, lo que implica vulnerabilidad ante ataques de intermediario. Tampoco implementa persistencia ni rotación de claves.

## Conclusión

KimoChat demuestra una arquitectura funcional de comunicación segura donde la confianza no depende del servidor. El servidor actúa únicamente como relay mediante `forward_unicast()`, los clientes gestionan la lógica de comunicación y handshake, y el módulo criptográfico asegura la confidencialidad.

El proyecto ilustra de forma clara cómo implementar un sistema de mensajería cifrada de extremo a extremo utilizando estándares modernos de criptografía.
