# RSA
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Signature import PKCS1_v1_5

# DSA
from Crypto.Signature import DSS
from Crypto.PublicKey import DSA
from Crypto import Random
from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

class PGPAuthentication:

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.key_pair = None

    def getPublicKeyDSA(self):
        return self.key_pair.publickey()

    def getPublicKeyRSA(self):
        return self.public_key

    def generate_rsa_keypair(self,key_size=2048):
        self.key_pair = RSA.generate(key_size)
        self.private_key = self.key_pair.export_key()
        self.public_key = self.key_pair.publickey().export_key()



    def encrypt_message_rsa(self, message, private_key):
        hash_msg = SHA1.new(message.encode())
        private_key_rsa_elem = RSA.import_key(private_key.decode())
        sender = PKCS1_v1_5.new(private_key_rsa_elem)
        signature = sender.sign(hash_msg)
        return signature

    def decrypt_message_rsa(self, message, signature,public_key):
        hash_msg = SHA1.new(message.encode())
        public_key_rsa_elem = RSA.import_key(public_key.decode())
        recipient = PKCS1_v1_5.new(public_key_rsa_elem)
        try:
            recipient.verify(hash_msg, signature)
            print("Signature is valid.")
            return True
        except ValueError:
            print("Signature is not valid.")
            return False

    def generate_dsa_keypair(self, key_size):

        private_key_obj = dsa.generate_private_key(
            key_size=key_size,
            backend=default_backend()
        )
        public_key_obj = private_key_obj.public_key()
        public_key = public_key_obj.public_bytes(encoding=serialization.Encoding.DER,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
        private_key = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        return private_key, public_key

    def encrypt_message_dsa(self, message, private_key_b):
        private_key = serialization.load_pem_private_key(
            private_key_b,
            password=None  # No password since the private key is not encrypted
        )
        return private_key.sign(message.encode(), hashes.SHA1())


    def decrypt_message_dsa(self, message, signature, public_key_b):

        public_key=serialization.load_der_public_key(public_key_b)
        try:
            public_key.verify(signature, message.encode(), hashes.SHA1())
            print("Signature is valid.")
        except InvalidSignature:
            print("Signature is not valid.")

pgp=PGPAuthentication()

# a,b=pgp.generate_dsa_keypair(1024)
# # public_bytes=b.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
# # lowest_64_bits=public_bytes[-8:]
#
# s=pgp.encrypt_message_dsa("ok",a)
# pgp.decrypt_message_dsa('ok',s,b)







