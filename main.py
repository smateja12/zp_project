
import io
import zipfile
import datetime
from ui.Message import Message
from ui.PGPAuthentication import PGPAuthentication
from ui.PGPConfidentiality import PGPConfidentiality
import base64
import pickle

def compress_data(message):
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('message.txt', message)

    memory_file.seek(0)

    compressed_data = memory_file.read()

    return compressed_data


def decompress_data(compressed):
    memory_file = io.BytesIO(compressed)

    with zipfile.ZipFile(memory_file, 'r') as zipf:
        filename = zipf.namelist()[0]
        decompressed = zipf.read(filename)
    return decompressed

def sending(confidentiality, authentication, compression, conversion, algorithm, key_size, message, algorithmSim, algorithm2, key_size2):

    pgpAuth = PGPAuthentication()
    keyIDRecipientPublicKey=0
    keyIDSendersPublicKey=0
    session_key_cipher_rsa =0
    nonce_ciphertext_tag=0
    keyID=0
    initial_message=message
    msg = Message(confidentiality=confidentiality, authentication=authentication, zip=compression,
                  radix64=conversion, filename=None, timestampM=datetime.datetime.now(), data=message)
    if authentication:
        if algorithm == "RSA":
            pgpAuth.generate_rsa_keypair(key_size)
            signature = pgpAuth.encrypt_message_rsa(message)
            message = str(signature) + "@@@" + message
            keyIDSendersPublicKey = pgpAuth.getPublicKeyRSA()
            nonce_ciphertext_tag=message
        else:
            pgpAuth.generate_dsa_keypair(key_size)
            signature = pgpAuth.encrypt_message_dsa(message)
            message = str(signature) + "@@@" + message
            keyID = pgpAuth.getPublicKeyDSA()
            nonce_ciphertext_tag = message
    if compression:
        # compression of message or signature
        message = compress_data(message)
        nonce_ciphertext_tag = message
    if confidentiality:
        pgpConf = PGPConfidentiality()
        if algorithm2 == "RSA" and algorithmSim == "AES":
            pgpConf.generate_keys_rsa(key_size2)
            for_sending = pgpConf.encrypt_message_rsa_aes(message, compression)
            strings = for_sending.split("@@@")
            session_key_cipher_rsa = strings[0]
            nonce_ciphertext_tag= strings[1]+"@@@"+strings[2]+"@@@"+strings[3]
            keyIDRecipientPublicKey=pgpConf.getPrivateKeyRSA()


        elif algorithm2 == "RSA" and algorithmSim == "3DES":
            pgpConf.generate_keys_rsa(key_size2)
            for_sending = pgpConf.encrypt_message_rsa_3des(message, compression)
            strings = for_sending.split("@@@")
            session_key_cipher_rsa = strings[0]
            nonce_ciphertext_tag = strings[1] + "@@@" + strings[2]
            keyIDRecipientPublicKey = pgpConf.getPrivateKeyRSA()

        elif algorithm2 == "ElGamal" and algorithmSim == "AES":
            pgpConf.generate_elgamal_keypair(key_size2)

            session_key_cipher_rsa,nonce_ciphertext_tag = pgpConf.encrypt_message_elgamal_aes(message, compression)

            keyIDRecipientPublicKey = pgpConf.getKeysElGamal()

        elif algorithm2 == "ElGamal" and algorithmSim == "3DES":
            pgpConf.generate_elgamal_keypair(key_size2)
            session_key_cipher_rsa,nonce_ciphertext_tag = pgpConf.encrypt_message_elgamal_3des(message, compression)
            keyIDRecipientPublicKey = pgpConf.getKeysElGamal()
    msg = Message(keyIDRecipientPublicKey, session_key_cipher_rsa, datetime.datetime.now(), keyIDSendersPublicKey,
                  False, nonce_ciphertext_tag, "message.txt", datetime.datetime.now(), initial_message)
    if conversion:
        serialized=pickle.dumps(msg)
        msg = base64.b64encode(serialized)

    return msg,keyID

def receiving(messageSent,keyID):

    if conversion:
        decoded_data = base64.b64decode(messageSent)
        messageSent = pickle.loads(decoded_data)
    message = messageSent.get_message_digest()
    if confidentiality:
        decrypted_message=0
        pgpConf = PGPConfidentiality()
        if algorithm2 == "RSA" and algorithmSim == "AES":

            decrypted_message = pgpConf.decrypt_message_rsa_aes(messageSent.get_session_key(),messageSent.get_message_digest(), compression,messageSent.get_keyIDRecipientPublicKey())

            print(decrypted_message)
        elif algorithm2 == "RSA" and algorithmSim == "3DES":
            decrypted_message = pgpConf.decrypt_message_rsa_3des(messageSent.get_session_key(),
                                                                messageSent.get_message_digest(), compression,
                                                                messageSent.get_keyIDRecipientPublicKey())
            print(decrypted_message)
        elif algorithm2 == "ElGamal" and algorithmSim == "AES":
            a,b=messageSent.get_keyIDRecipientPublicKey()
            decrypted_message = pgpConf.decrypt_message_elgamal_aes(messageSent.get_session_key(),
                                                                 messageSent.get_message_digest(), compression,
                                                                 a,b)
            print(decrypted_message)
        elif algorithm2 == "ElGamal" and algorithmSim == "3DES":
            a, b = messageSent.get_keyIDRecipientPublicKey()
            decrypted_message = pgpConf.decrypt_message_elgamal_3des(messageSent.get_session_key(),
                                                                    messageSent.get_message_digest(), compression,
                                                                    a, b)
            print(decrypted_message)
        if compression:
            message = decompress_data(decrypted_message).decode()
            print(message)
        else:
            message = decrypted_message
    if (not confidentiality) and compression:

        message = decompress_data(messageSent.get_message_digest()).decode()
        print(message)

    if authentication:
        if algorithm == "RSA":
            pgpAuth = PGPAuthentication()
            msg = message.split("@@@")
            pgpAuth.decrypt_message_rsa(msg[1], eval(msg[0]),messageSent.get_keyIDSendersPublicKey())
        else:
            pgpAuth = PGPAuthentication()
            msg = message.split("@@@")
            pgpAuth.decrypt_message_dsa(msg[1], eval(msg[0]), keyID)



confidentiality = True
authentication = True
compression = True
conversion = True
message = "Hello world"

algorithm = "DSA" # RSA/DSA
key_size = 2048 #1024/2048
algorithmSim = "3DES" #AES/3DES
algorithm2 = "ElGamal" #RSA/ElGamal
key_size2 = 2048 #1024/2048

msg,keyid=sending(confidentiality, authentication, compression, conversion, algorithm, key_size, message, algorithmSim, algorithm2, key_size2)

receiving(msg,keyid)

