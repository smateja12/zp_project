import io
import os
import random

import zipfile
import sympy
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA, ElGamal

from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getStrongPrime,long_to_bytes,bytes_to_long

class PGPConfidentiality:
    def __init__(self):
        self.private_key_recipient = None
        self.public_key_recipient = None
        self.key_pair_recipient = None
        self.session_key = None

    def generate_session_key(self, key_size=256):
        self.session_key = random.getrandbits(key_size)

    def generate_session_key_rsa(self):
        self.session_key = os.urandom(24)

    def getKeysElGamal(self):
        return self.public_key_recipient, self.private_key_recipient

    def getPrivateKeyRSA(self):
        return self.private_key_recipient
    # RSA
    def generate_rsa_keypair(self,key_size=2048):
        self.key_pair_recipient = RSA.generate(key_size)
        self.private_key_recipient = self.key_pair_recipient.export_key()
        self.public_key_recipient = self.key_pair_recipient.publickey().export_key()

    def set_rsa_keypair(self,public_key):

        self.public_key_recipient = public_key

    def generate_keys_rsa(self,public_key):
        self.set_rsa_keypair(public_key)
        self.generate_session_key_rsa()

    def encrypt_message_rsa_3des(self, message,kompresija):
        # Encrypt session_key with the recipient's public key using RSA
        public_key_recipient_obj = RSA.import_key(self.public_key_recipient)
        public_key_recipient_cipher = PKCS1_OAEP.new(public_key_recipient_obj)
        session_key_cipher_rsa = public_key_recipient_cipher.encrypt(self.session_key)

        # Encrypt the message with session_key using 3DES
        init_val = os.urandom(8)
        cipher_3des = DES3.new(self.session_key, DES3.MODE_CBC, init_val)
        if kompresija:
            message_pad = pad(message, DES3.block_size)
        else:
            message_pad = pad(message.encode(), DES3.block_size)


        #message_padd = pad(message.encode(), 8)
        message_cipher = cipher_3des.encrypt(message_pad)
        return str(session_key_cipher_rsa)+"@@@"+str(init_val)+"@@@"+str(message_cipher)

    def decrypt_message_rsa_3des(self, encrypt_session_key,encrypt_ciphertext,kompresija,private_key_recipient):
        session_key_cipher_rsa = eval(encrypt_session_key)
        strings = encrypt_ciphertext.split("@@@")
        init_val = eval(strings[0])
        message_cipher = eval(strings[1])

        # Decrypt session_key with the recipient's private key using RSA
        private_key_recipient_rsa = RSA.import_key(private_key_recipient)
        private_key_recipient_obj = PKCS1_OAEP.new(private_key_recipient_rsa)
        session_key = private_key_recipient_obj.decrypt(session_key_cipher_rsa)

        # Decrypt the message using session_key and 3DES
        cipher_3des = DES3.new(session_key, DES3.MODE_CBC, init_val)
        message_padd = cipher_3des.decrypt(message_cipher)
        message = unpad(message_padd, 8)
        if kompresija:
            return message
        else:
            plaintext = message.decode()
            return plaintext

    def encrypt_message_rsa_aes(self, message,kompresija):
        # Encrypt session_key with the recipient's public key using RSA
        public_key_recipient_obj = RSA.import_key(self.public_key_recipient)
        public_key_recipient_cipher = PKCS1_OAEP.new(public_key_recipient_obj)
        session_key_cipher_rsa = public_key_recipient_cipher.encrypt(self.session_key)

        # Encrypt the message with session_key using AES
        aes_cipher = AES.new(self.session_key, AES.MODE_EAX)
        nonce = aes_cipher.nonce
        if kompresija:
            ciphertext, tag = aes_cipher.encrypt_and_digest(message)
        else:
            ciphertext, tag = aes_cipher.encrypt_and_digest(message.encode())

        return str(session_key_cipher_rsa)+"@@@"+ str(nonce)+"@@@"+ str(ciphertext)+"@@@"+ str(tag)

    def decrypt_message_rsa_aes(self, encrypt_session_key,encrypt_message_digest,kompresija,private_key_recipient):

        session_key_cipher_rsa = eval(encrypt_session_key)
        strings=encrypt_message_digest.split("@@@")
        nonce = eval(strings[0])
        ciphertext = eval(strings[1])
        tag = eval(strings[2])

        # Decrypt session_key with the recipient's private key using RSA
        private_key_recipient_obj = RSA.import_key(private_key_recipient)
        private_key_recipient_cipher = PKCS1_OAEP.new(private_key_recipient_obj)
        session_key = private_key_recipient_cipher.decrypt(session_key_cipher_rsa)

        # Decrypt the message using session_key and AES
        aes_cipher = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_message = aes_cipher.decrypt_and_verify(ciphertext, tag)
        if kompresija:
            return decrypted_message
        else:
            plaintext = decrypted_message.decode()
            return plaintext

    # ElGamal
    def generate_elgamal_keypair(self, key_size=2048):
        if key_size not in [1024, 2048]:
            print("Velicina kljuca moze biti samo 1024/2048 bita")
            return None

        prime_bits = key_size // 2
        q = getStrongPrime(prime_bits)

        alfa = 2
        while True:
            h = random.randint(2, q - 1)
            if pow(h, (q - 1) // 2, q) != 1:
                break

        Xa = random.randint(2, q - 2)
        Ya = pow(alfa, Xa, q)

        self.private_key_recipient = Xa
        self.public_key_recipient = (q, alfa, h, Ya)


    def set_elgamal_key(self,public_key):
        self.public_key_recipient=public_key

    def encrypt_message_elgamal_aes(self, message,kompresija):


        # generate new session key
        self.generate_session_key(128)

        # Encrypt session_key with the recipient's public key using ElGamal algo
        session_key_encrypted = self.elgamal_encrypt(self.session_key)

        # Encrypt the message with session_key using AES
        cipher_message = self.aes_encrypt(message, self.session_key,kompresija)

        # print("Session key encrypted: " + str(session_key_encrypted))
        # print("Message encrypted: " + str(cipher_message))

        return session_key_encrypted, cipher_message

    def decrypt_message_elgamal_aes(self, session_key_encrypted,cipher_message,kompresija,public_key_recipient,private_key_recipient):


        session_key = self.elgamal_decrypt(session_key_encrypted,public_key_recipient,private_key_recipient)

        message_plain = self.aes_decrypt(cipher_message, session_key,kompresija)

        return message_plain

    def elgamal_encrypt(self, message):
        q, alfa, h, Ya = self.public_key_recipient

        num = random.randint(2, q - 2)

        c1 = pow(alfa, num, q)
        s = pow(Ya, num, q)
        c2 = (s * message) % q

        return c1, c2

    def elgamal_decrypt(self, ciphertext,public_key_recipient,private_key_recipient):
        c1, c2 = eval(ciphertext)
        q, alfa, h, Ya = public_key_recipient

        s = pow(c1, private_key_recipient, q)
        s_inv = sympy.invert(s, q)

        plaintext = (c2 * s_inv) % q

        return plaintext

    def aes_encrypt(self, message, session_key,kompresija):
        session_key_in_bytes = self.int_to_bytes(session_key)
        cipher_aes = AES.new(session_key_in_bytes, AES.MODE_ECB)
        if kompresija:
            message_pad = pad(message, AES.block_size)
        else:
            message_pad = pad(message.encode(), AES.block_size)
        message_cipher = cipher_aes.encrypt(message_pad)
        return message_cipher

    def des3_encrypt(self, message, session_key,kompresija):
        session_key_in_bytes = self.int_to_bytes(session_key)
        cipher = DES3.new(session_key_in_bytes, DES3.MODE_ECB)
        if kompresija:
            message_pad = pad(message, DES3.block_size)
        else:
            message_pad = pad(message.encode(), DES3.block_size)

        message_cipher = cipher.encrypt(message_pad)
        return message_cipher

    def aes_decrypt(self, ciphertext, session_key,kompresija):
        session_key_in_bytes = self.int_to_bytes(session_key)
        cipher_aes = AES.new(session_key_in_bytes, AES.MODE_ECB)
        decrypted_message_pad = cipher_aes.decrypt(eval(ciphertext))
        message_plain = unpad(decrypted_message_pad, AES.block_size)
        if kompresija:
            return message_plain
        else:
            plaintext = message_plain.decode()
            return plaintext

    def des3_decrypt(self, ciphertext, session_key,kompresija):
        session_key_in_bytes = self.int_to_bytes(session_key)
        cipher = DES3.new(session_key_in_bytes, DES3.MODE_ECB)
        decrypted_message_pad = cipher.decrypt(eval(ciphertext))
        message = unpad(decrypted_message_pad, DES3.block_size)
        if kompresija:
            return message
        else:
            plaintext = message.decode()
            return plaintext

    def int_to_bytes(self, num):
        num_hex = hex(num)[2:]  # Remove the '0x' prefix from the hex string
        if len(num_hex) % 2 != 0:
            num_hex = '0' + num_hex  # Add a leading zero if the hex string has an odd length
        byte_str = bytes.fromhex(num_hex)
        return byte_str

    def encrypt_message_elgamal_3des(self, message,kompresija):


        # generate new session key
        self.generate_session_key(128)

        # Encrypt session_key with the recipient's public key using ElGamal algo
        session_key_encrypted = self.elgamal_encrypt(self.session_key)

        cipher_message = self.des3_encrypt(message, self.session_key,kompresija)

        return session_key_encrypted, cipher_message

    def decrypt_message_elgamal_3des(self,session_key_encrypted,cipher_message,kompresija,public_key_recipient,private_key_recipient):



        session_key = self.elgamal_decrypt(session_key_encrypted,public_key_recipient,private_key_recipient)

        message_plain = self.des3_decrypt(cipher_message, session_key,kompresija)


        return message_plain

    def compress_data(self, message):
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr('message.txt', message)

        memory_file.seek(0)

        compressed_data=memory_file.read()

        return compressed_data

    def decompress_data(self, compressed):
        memory_file=io.BytesIO(compressed)

        with zipfile.ZipFile(memory_file,'r') as zipf:
            filename=zipf.namelist()[0]
            decompressed=zipf.read(filename)
        return decompressed

