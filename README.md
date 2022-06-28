# python-encrypted-chatroom

Server client encrypted chatroom:
* Server-client authentication: ECDSA
* Key exchange: X25519
* Message authentication: SHA256

To successfully start the chatroom, run the scripts in the following order:
1. python3 config.py
2. python3 server.py
3. python3 client.py
