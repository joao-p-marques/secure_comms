from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import sys

#I think that having 4096 is too lengthy and not practical in real life
KEY_SIZE = 2048

def createRSA(file_private,file_public, key_length):
    #Readfile

    #SHA-1
    if key_length=="1":
        KEY_SIZE = 1024
    
    #SHA-2 256 bits
    elif key_length=="2":
        KEY_SIZE = 2048

    #SHA-2 384 bits
    elif key_length=="3":
        KEY_SIZE = 3072

    #SHA-2 512 bits
    elif key_length=="4":
        KEY_SIZE = 4096

    else:
        print("Hash type invalid, try again.")
        sys.exit(0)

    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=KEY_SIZE
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PublicFormat.PKCS1
    )

    with open(file_private, 'wb') as f:
        f.write(private_key)

    with open(file_public, 'wb') as f:
        f.write(public_key)


menu = "What key length would you like? \n(1) - 1024\n(2) - 2048\n(3) - 3072\n(4) - 4096\n-> "

key_length = input(menu)
file_private = input("\nNome ficheiro chave privada? -> ")
file_public = input("\nNome ficheiro chave publica? -> ")


createRSA(file_private,file_public,key_length)