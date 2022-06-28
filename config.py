import configparser

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

private_key_client = ec.generate_private_key(ec.SECP384R1())

private_bytes_client_pem = private_key_client.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'0000')
)

public_key_client = private_key_client.public_key()
public_bytes_client_pem = public_key_client.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

private_key_server= ec.generate_private_key(ec.SECP384R1())
private_bytes_server_pem = private_key_server.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'0000')
)

public_key_server = private_key_server.public_key()
public_bytes_server_pem = public_key_server.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

config = configparser.ConfigParser()

config['DEFAULT'] = {}
config['DEFAULT']['port'] = '59000'
config['DEFAULT']['key_prv_client'] = private_bytes_client_pem.decode()
config['DEFAULT']['key_pub_client'] = public_bytes_client_pem.decode()
config['DEFAULT']['key_prv_server'] = private_bytes_server_pem.decode()
config['DEFAULT']['key_pub_server'] = public_bytes_server_pem.decode()

with open('config.conf', 'w') as configfile:
    config.write(configfile)

configfile.close()