import configparser
import threading
import socket
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import x25519
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
import pickle

#Load the configuration
CONFIG = configparser.ConfigParser()
CONFIG.read('config.conf')

HOST = socket.gethostname()
PORT = int(CONFIG['DEFAULT']['port'])

SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER.bind((HOST, PORT))
SERVER.listen()

CLIENTS = []
USERNAMES = []
SHARED_KEYS = []

ECDSA_PRIVATE_KEY_SERVER = bytes(CONFIG['DEFAULT']['key_prv_server'], encoding='utf-8')
ECDSA_PRIVATE_KEY_SERVER = serialization.load_pem_private_key(ECDSA_PRIVATE_KEY_SERVER, password = b'0000')

ECDSA_PUBLIC_KEY_CLIENT = bytes(CONFIG['DEFAULT']['key_pub_client'], encoding='utf-8')
ECDSA_PUBLIC_KEY_CLIENT = serialization.load_pem_public_key(ECDSA_PUBLIC_KEY_CLIENT)

X25519_PRIVATE_KEY_SERVER = X25519PrivateKey.generate()
X25519_PUBLIC_KEY_SERVER = X25519_PRIVATE_KEY_SERVER.public_key()
X25519_PUBLIC_KEY_SERVER = X25519_PUBLIC_KEY_SERVER.public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)

#Create a signature with X25519_PUBLIC_KEY_SERVER and ECDSA_PRIVATE_KEY_SERVER
SIGNATURE_SERVER = ECDSA_PRIVATE_KEY_SERVER.sign(X25519_PUBLIC_KEY_SERVER, ec.ECDSA(hashes.SHA256()))

#Create authentication packet by merging the SIGNATURE (bytes) with X25519_PUBLIC_KEY_SERVER
AUTH_PACKET_SERVER = X25519_PUBLIC_KEY_SERVER + pickle.dumps(SIGNATURE_SERVER)

def hash_message(message):
    '''
    Hash the message with SHA256
    '''
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()

def server_broadcast_message(message, sender):
    '''
    Get client shared_key (b64 encoded) and encrypt it.
    Send the message to all connected clients.
    '''
    for client in CLIENTS:
        if (client == sender): continue
        shared_key = SHARED_KEYS[CLIENTS.index(client)]
        message_encrypted = shared_key.encrypt(message)
        client.send(message_encrypted)

def server_handle_client(client):
    '''
    Handles all messages from clients (implements broadcast
    to send messages to all clients). If the message can't
    be sent to a client remove the client from the lists
    (CIENTS, USERNAMES, SHARED_KEYS) and print that the 
    client has left the chat.
    '''
    index = CLIENTS.index(client)

    shared_key = SHARED_KEYS[index]
    username = USERNAMES[index]

    while True:
        try:
            message = client.recv(4096)
            print(f'[RECEIVED ENCRYPTED MESSAGE]', message)
            
            message = shared_key.decrypt(message)
            
            #If the message is decrypted successfuly broadcast the packet (hash + message).
            if (hash_message(message[32:]) == message[:32]):
                print(f'[INTEGRITY CHECK] VERIFIED!')
                print(f'[DECRYTPED MESSAGE CONTENT]', message[32:].decode('utf-8'), '\n')
                server_broadcast_message(message, client)
            else:
                #If the packet is corrupted or an error occured during the decryption drop it.
                print(f'[INTEGRITY CHECK] CORRUPTED!')
            
        except Exception as exc:
            print('[ERROR]', exc)
            CLIENTS.remove(client)
            USERNAMES.remove(username)
            SHARED_KEYS.remove(shared_key)
            client.close()
            sys.exit()

def server_receive():
    '''
    Connects client and server (SERVER.accept()) - waits for connection all the time.
    Thread enables multiple users to be active at the same time (handle_client).
    '''
    while True:
        print(f'Server is running and listening...\n')
        
        client, address = SERVER.accept()
        print(f'Connection is established with {str(address)}')
        
        client.send('username?'.encode('utf-8'))
        username = client.recv(4096)

        USERNAMES.append(username)
        CLIENTS.append(client)
        print(f'[USERNAME]', username.decode('utf-8'))

        #If the client verifies the identity of the server via ECDSA_PUBLIC_KEY_SERVER will send its AUTH_PACKET
        client.send(AUTH_PACKET_SERVER)

        auth_packet_client = client.recv(4096)
        x25519_public_key_client = auth_packet_client[:32]
        signature_client = pickle.loads(auth_packet_client[32:])
        
        #Verfiy the identity of the client using client ECDSA public key
        try:
            ECDSA_PUBLIC_KEY_CLIENT.verify(signature_client, x25519_public_key_client, ec.ECDSA(hashes.SHA256()))
            client.send('[SERVER <-> CLIENT CONNECTION AUTHENTICATED]'.encode('utf-8'))
            
            #If the verification is success then a shared X25519 key will be calculated
            loaded_public_key_client = x25519.X25519PublicKey.from_public_bytes(x25519_public_key_client)
            shared_key_raw = X25519_PRIVATE_KEY_SERVER.exchange(loaded_public_key_client)
            print(f'[SERVER <->', username.decode('utf-8').upper(), f'SHARED KEY]', shared_key_raw, f'\n')
            
            #Add the shared key of the client to the list 
            SHARED_KEYS.append(Fernet(b64encode(shared_key_raw)))

        except Exception as exc:
            client.send('[CLIENT AUTHENTICATION FAILED]'.encode('utf-8'))
            print(f'[CLIENT AUTHENTICATION FAILED]\n', exc)
        
        thread = threading.Thread(target=server_handle_client, args=(client,))
        thread.start()

if __name__ == '__main__':
    '''
    Kill server (Linux): sudo lsof -i:59000, kill $PID
    '''
    server_receive()