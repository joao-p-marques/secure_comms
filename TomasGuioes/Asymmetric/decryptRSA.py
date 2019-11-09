from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys


def decryptRSA(file_origin, file_public, file_goal):
    #Readfile
    try:
        with open(file_origin, 'rb') as f:
            texto = f.read()

    except:
        print("Invalid origin file.")
        sys.exit(0)

    try:
        with open(file_public, 'rb') as f:
            private_key = crypto_serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=crypto_default_backend()
            )

    except:
        print("Invalid public key file.")
        sys.exit(0)
    
    decrypted_text = private_key.decrypt(
        texto,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Ficheiro desencriptado: %s" % (decrypted_text))
    with open(file_goal, 'wb') as f:
            f.write(decrypted_text)


file_origin = input("\nNome ficheiro encriptado -> ")
file_public = input("Nome ficheiro com chave publica -> ")
file_goal = input("Nome ficheiro desencriptado -> ")


decryptRSA(file_origin,file_public,file_goal)