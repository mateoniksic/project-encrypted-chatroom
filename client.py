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

CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
CLIENT.connect((HOST, PORT))

USERNAME = input('[ENTER YOUR USERNAME] ')

ECDSA_PRIVATE_KEY_CLIENT = bytes(CONFIG['DEFAULT']['key_prv_client'], encoding='utf-8')
ECDSA_PRIVATE_KEY_CLIENT = serialization.load_pem_private_key(ECDSA_PRIVATE_KEY_CLIENT, password=b'0000')

ECDSA_PUBLIC_KEY_SERVER = bytes(CONFIG['DEFAULT']['key_pub_server'], encoding='utf-8')
ECDSA_PUBLIC_KEY_SERVER = serialization.load_pem_public_key(ECDSA_PUBLIC_KEY_SERVER)

X25519_PRIVATE_KEY_CLIENT = X25519PrivateKey.generate()
X25519_PUBLIC_KEY_CLIENT = X25519_PRIVATE_KEY_CLIENT.public_key()
X25519_PUBLIC_KEY_CLIENT = X25519_PUBLIC_KEY_CLIENT.public_bytes( encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)

SHARED_KEY = ''

#Create a signature with X25519_PUBLIC_KEY_SERVER and ECDSA_PRIVATE_KEY_CLIENT
SIGNATURE_CLIENT = ECDSA_PRIVATE_KEY_CLIENT.sign(X25519_PUBLIC_KEY_CLIENT, ec.ECDSA(hashes.SHA256()))

#Create authentication packet by merging the SIGNATURE (bytes) with X25519_PUBLIC_KEY_CLIENT
AUTH_PACKET_CLIENT = X25519_PUBLIC_KEY_CLIENT + pickle.dumps(SIGNATURE_CLIENT)

def hash_message(message):
    '''
    Hash the message with SHA256
    '''
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()

def client_receive():
    '''
    Defines how the user receives and decrypts the message.
    '''
    while True:
        try:
            message = CLIENT.recv(4096)
            
            if (len(message) == 0): continue

            print(f'[RECEIVED ENCRYPTED MESSAGE]', message)    
            
            #Decrypt the received message
            message = SHARED_KEY.decrypt(message)
            
            #Check the integrity of the message, the first 32 bytes are hash, rest is the message
            if (hash_message(message[32:]) == message[:32]):
                print(f'[INTEGRITY CHECK] VERIFIED!')
                print(f'[DECRYTPED MESSAGE CONTENT]', message[32:].decode('utf-8'))
            else:
                print(f'[INTEGRITY CHECK] CORRUPTED!')
            
        except Exception as exc:
            print('[ERROR]', exc)
            CLIENT.close()
            sys.exit()

def client_send():
    '''
    Defines how the user sends and encrypts the message.
    '''
    while True:
        try:
            message = f'{USERNAME}: {input("")}'

            #Merge the hash and the message into single packet
            message = hash_message(message.encode('utf-8')) + message.encode('utf-8')
            message = SHARED_KEY.encrypt(message)
            CLIENT.send(message)

        except Exception as exc:
            print('[ERROR]', exc)
            sys.exit()

if __name__ == '__main__':

    try:
        message = CLIENT.recv(4096).decode('utf-8')

        if message == 'username?':
            CLIENT.send(USERNAME.encode('utf-8'))
            
            #Start server authentication
            auth_packet_server = CLIENT.recv(4096)
            x25519_public_key_server = auth_packet_server[:32]
            signature_server = pickle.loads(auth_packet_server[32:])
            
            #Verfiy the identity of the client using server ECDSA public key
            try:
                ECDSA_PUBLIC_KEY_SERVER.verify(signature_server, x25519_public_key_server, ec.ECDSA(hashes.SHA256()))
                CLIENT.send(AUTH_PACKET_CLIENT)
                
                connection_status_message = CLIENT.recv(4096).decode('utf-8')
                print(connection_status_message)

                if connection_status_message == "[CLIENT AUTHENTICATION FAILED]": quit()
                
                #If the verification is success then a shared X25519 key will be calculated
                loaded_public_key_server = x25519.X25519PublicKey.from_public_bytes(x25519_public_key_server)
                shared_key_raw = X25519_PRIVATE_KEY_CLIENT.exchange(loaded_public_key_server)

                SHARED_KEY = Fernet(b64encode(shared_key_raw))
                print(f'[SERVER <->', USERNAME.upper(), f'SHARED KEY]', shared_key_raw, f'\n')

            except Exception as exc:
                print(f'[SERVER AUTHENTICATION FAILED]\n', exc)

        else:
            print(message)

    except Exception as exc:
        print('[ERROR]', exc)
        CLIENT.close()
    
    receive_thread = threading.Thread(target=client_receive)
    receive_thread.start()

    send_thread = threading.Thread(target=client_send)
    send_thread.start()
