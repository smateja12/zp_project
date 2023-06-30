import base64
import datetime
import hashlib
import pickle

from Crypto import Random

from Crypto.Cipher import CAST
from Crypto.PublicKey import DSA, RSA
from Crypto.Util import Padding
from PyQt5 import QtWidgets, uic
from PyQt5.QtWidgets import QFileDialog, QInputDialog
import io
import zipfile
from PyQt5 import QtCore
from ElGamal import ElGamal

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

from ui.Message import Message
from ui.PGPAuthentication import PGPAuthentication
from ui.PGPConfidentiality import PGPConfidentiality
from PrivateKeyRing import *
from PublicKeyRing import *
from pathlib import Path


Ui_MainWindow, _ = uic.loadUiType("my.ui")
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




class MyMainWindow(QtWidgets.QMainWindow,Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.showMaximized()
        self.setWindowTitle("Project")
        self.privateKeyUserID.setVisible(False)
        self.publicKeyUserID.setVisible(False)
        self.algorithmConf_CB.setVisible(False)
        self.label_11.setVisible(False)
        self.label_12.setVisible(False)
        self.generateButton.clicked.connect(self.fill_form)
        self.nextButton.clicked.connect(self.go_to_next_page)
        self.previousButton.setEnabled(False)
        self.key_id_LE.setReadOnly(True)
        self.previousButton.clicked.connect(self.go_to_previous_page)
        self.sendButton.clicked.connect(self.sendMessage)
        self.confidentiality_CB.clicked.connect(self.on_conf_clicked)
        self.Authentication_CB.clicked.connect(self.on_auth_clicked)
        self.fileButton.clicked.connect(self.chooseFile)
        self.file_LE.setReadOnly(True)
        self.private_key_ring=PrivateKeyRing()
        self.public_key_ring = PublicKeyRing()
        self.populate_PrivateKeyRing()
        self.populate_PublicKeyRing()
        self.private_key = None
        self.public_key = None
        self.recieveButton.clicked.connect(self.recieveFile)
        self.original_message=None
        self.saveButton.clicked.connect(self.saveFile)
        self.publicKeyUserID.currentIndexChanged.connect(self.publicKeyChanged)
        self.privateKeyUserID.currentIndexChanged.connect(self.privateKeyChanged)
        self.importButton.clicked.connect(self.import_key)

    def import_key(self):

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File", "", "", options=options)


        # proveriti tip fajla koji se uvozi

        file_type = Path(file_name).suffix.lower()
        if file_type != ".pem":
            print("Input file is not a PEM file")
            return
        with open(file_name, 'r') as pem_file:
            lines = pem_file.readlines()

            # public key ring row
            timestamp1 = lines[1]
            key_id1 = lines[2]
            public_key1 = lines[3]
            user_email1 = lines[4]
            user_name1 = lines[5]
            hash_user_password1 = lines[6]
            algorithm1 = lines[7]
            key_size1 = lines[8]

            # private key ring row
            timestamp2 = lines[11]
            key_id2 = lines[12]
            public_key2 = lines[13]
            encrypted_private_key2 = lines[14]
            user_email2 = lines[15]
            user_name2 = lines[16]
            hash_user_password2 = lines[17]
            algorithm2 = lines[18]
            key_size2 = lines[19]

            public_key_ring_elem = PublicKeyRingElem(timestamp=timestamp1,
                                                     key_id=key_id1,
                                                     public_key=public_key1,
                                                     user_email=user_email1,
                                                     user_name=user_name1,
                                                     hash_user_password=hash_user_password1,
                                                     algorithm=algorithm1,
                                                     key_size=key_size1)

            self.public_key_ring.public_key_ring_insert(key_id1, public_key_ring_elem)

            private_key_ring_elem = PrivateKeyRingElem(timestamp=timestamp2,
                                                       key_id=key_id2,
                                                       public_key=public_key2,
                                                       encrypted_private_key=encrypted_private_key2,
                                                       user_email=user_email2,
                                                       user_name=user_name2,
                                                       hash_user_password=hash_user_password2,
                                                       algorithm=algorithm2,
                                                       key_size=key_size2
                                                       )

            self.private_key_ring.private_key_ring_insert(key_id2, private_key_ring_elem)

        print("Successfully imported key")
        self.populate_PublicKeyRing()
        self.populate_PrivateKeyRing()

    def export_key(self):
        button=app.sender()
        key_id=eval(button.objectName())
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "", options=options)

        # za trazeni key_id kreirati pem file
        # dohvatiti private_key_ring_row
        # dohvatiti public_key_ring_row

        # -----BEGIN PRIVATE KEY-----
        # -----END PRIVATE KEY-----
        # -----BEGIN PUBLIC KEY-----
        # -----END PUBLIC KEY-----

        public_key_ring = self.get_gui_public_key_ring()
        private_key_ring = self.get_gui_private_key_ring()

        public_key_ring_row = public_key_ring.get_row(key_id)
        private_key_ring_row = private_key_ring.get_row(key_id)

        print("PUBLIC ROW: " + str(public_key_ring_row))
        print("PRIVATE ROW: " + str(private_key_ring_row))

        if public_key_ring_row is None or private_key_ring_row is None:
            print("Unsuccessfully exported key")
            return

        timestamp = public_key_ring_row.get_timestamp()
        key_id = public_key_ring_row.get_key_id()
        public_key = public_key_ring_row.get_public_key()
        user_email = public_key_ring_row.get_user_email()
        user_name = public_key_ring_row.get_user_name()
        hash_user_password = public_key_ring_row.get_hash_user_password()
        algorithm = public_key_ring_row.get_algorithm()
        key_size = public_key_ring_row.get_key_size()
        encrypted_private_key = private_key_ring_row.get_encrypted_private_key()

        data_to_write = "-----BEGIN PUBLIC KEY RING ROW-----\n"
        data_to_write += str(str(timestamp) + '\n')
        data_to_write += str(str(key_id) + '\n')
        data_to_write += str(str(public_key) + '\n')
        data_to_write += str(str(user_email) + '\n')
        data_to_write += str(str(user_name) + '\n')
        data_to_write += str(str(hash_user_password) + '\n')
        data_to_write += str(str(algorithm) + '\n')
        data_to_write += str(str(key_size) + '\n')
        data_to_write += "-----END PUBLIC KEY RING ROW-----\n"

        data_to_write += "-----BEGIN PRIVATE KEY RING ROW-----\n"
        data_to_write += str(str(timestamp) + '\n')
        data_to_write += str(str(key_id) + '\n')
        data_to_write += str(str(public_key) + '\n')
        data_to_write += str(str(encrypted_private_key) + '\n')
        data_to_write += str(str(user_email) + '\n')
        data_to_write += str(str(user_name) + '\n')
        data_to_write += str(str(hash_user_password) + '\n')
        data_to_write += str(str(algorithm) + '\n')
        data_to_write += str(str(key_size) + '\n')
        data_to_write += "-----END PRIVATE KEY RING ROW-----\n"

        # sacuvati sav sadrzaj u ovaj file
        with open(file_path, 'w') as file:
            file.write(data_to_write)
        print("Successfully exported key")

    def remove_key_pair(self):
        button = app.sender()
        key_id = eval(button.objectName())

        public_key_ring = self.get_gui_public_key_ring()
        private_key_ring = self.get_gui_private_key_ring()

        public_key_ring_row = public_key_ring.get_row(key_id)
        private_key_ring_row = private_key_ring.get_row(key_id)
        key_id_public = public_key_ring_row.get_key_id()
        key_id_private = private_key_ring_row.get_key_id()

        if public_key_ring_row is None or private_key_ring_row is None or (key_id_public != key_id_private):
            print("Unsuccessfully removed key pair")
            return

        public_key_ring.public_key_ring_remove(key_id_public)
        private_key_ring.private_key_ring_remove(key_id_private)
        print("Successfully removed key pair")
        self.populate_PrivateKeyRing()
        self.populate_PublicKeyRing()




    def publicKeyChanged(self):
        selected=self.publicKeyUserID.currentText()
        if selected=="":
            public_key_ring_iter = self.public_key_ring.get_public_key_ring()
            for key, value in public_key_ring_iter.items():
                if value.algorithm == "DSA" or value.algorithm == "RSA":
                    # show
                    index = self.privateKeyUserID.findText(str(key))
                    if index == -1:
                        index = self.privateKeyUserID.count()
                        self.privateKeyUserID.insertItem(index, str(key))
            return

        publicKey = self.public_key_ring.get_row(eval(selected))
        algorithm2 = publicKey.get_algorithm()
        if algorithm2=="RSA":

            public_key_ring_iter=self.public_key_ring.get_public_key_ring()
            for key, value in public_key_ring_iter.items():
                if value.algorithm=="DSA":
                    # hide
                    index=self.privateKeyUserID.findText(str(key))
                    if index != -1:
                        self.privateKeyUserID.removeItem(index)
                elif value.algorithm=="RSA":
                    # show
                    index = self.privateKeyUserID.findText(str(key))
                    if index == -1:
                        index=self.privateKeyUserID.count()
                        self.privateKeyUserID.insertItem(index,str(key))

        elif algorithm2=="ElGamal":
            public_key_ring_iter = self.public_key_ring.get_public_key_ring()
            for key, value in public_key_ring_iter.items():
                if value.algorithm=="RSA":
                    #hide
                    index=self.privateKeyUserID.findText(str(key))
                    if index != -1:
                        self.privateKeyUserID.removeItem(index)
                elif value.algorithm == "DSA":
                    #show
                    index = self.privateKeyUserID.findText(str(key))
                    if index == -1:
                        index = self.privateKeyUserID.count()
                        self.privateKeyUserID.insertItem(index, str(key))


    def privateKeyChanged(self):


        selected=self.privateKeyUserID.currentText()
        if selected=="":
            public_key_ring_iter = self.public_key_ring.get_public_key_ring()
            for key, value in public_key_ring_iter.items():
                if value.algorithm == "RSA" or value.algorithm == "ElGamal":
                    # show
                    index = self.publicKeyUserID.findText(str(key))
                    if index == -1:
                        index = self.publicKeyUserID.count()
                        self.publicKeyUserID.insertItem(index, str(key))
            return
        privateKey = self.private_key_ring.get_row(eval(selected))

        algorithm2 = privateKey.get_algorithm()
        if algorithm2 == "RSA":

            public_key_ring_iter = self.public_key_ring.get_public_key_ring()
            for key, value in public_key_ring_iter.items():
                if value.algorithm == "ElGamal":
                    # hide
                    index = self.publicKeyUserID.findText(str(key))
                    if index != -1:
                        self.publicKeyUserID.removeItem(index)
                elif value.algorithm == "RSA":
                    # show
                    index = self.publicKeyUserID.findText(str(key))
                    if index == -1:
                        index = self.publicKeyUserID.count()
                        self.publicKeyUserID.insertItem(index, str(key))


        elif algorithm2 == "DSA":
            public_key_ring_iter = self.public_key_ring.get_public_key_ring()
            for key, value in public_key_ring_iter.items():
                if value.algorithm == "RSA":
                    # hide
                    index = self.publicKeyUserID.findText(str(key))
                    if index != -1:
                        self.publicKeyUserID.removeItem(index)
                elif value.algorithm == "ElGamal":
                    #show
                    index = self.publicKeyUserID.findText(str(key))
                    if index == -1:
                        index = self.publicKeyUserID.count()
                        self.publicKeyUserID.insertItem(index, str(key))

    def saveFile(self):
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getSaveFileName(self, "Save File", "", "Text Files (*.txt)",
                                                  options=options)
        if filename:
            with open(filename, "w") as f:
                f.write(self.original_message)

    def recieveFile(self):
        options=QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File","","Text Files (*.txt)",options=options)
        self.recieveMessage(file_name)


    def get_gui_public_key_ring(self):
        return self.public_key_ring

    def get_gui_private_key_ring(self):
        return self.private_key_ring

    def chooseFile(self):
        options=QFileDialog.Options()
        filename, _ =QFileDialog.getSaveFileName(self,"Save File","","Text Files (*.txt)",options=options)
        if filename:
            self.file_LE.setText(filename)

    def on_auth_clicked(self):
        if self.Authentication_CB.isChecked():
            self.privateKeyUserID.setVisible(True)
            self.label_11.setVisible(True)
        else:
            self.privateKeyUserID.setCurrentIndex(0)
            self.privateKeyUserID.setVisible(False)
            self.label_11.setVisible(False)


    def on_conf_clicked(self):
        if self.confidentiality_CB.isChecked():
            self.publicKeyUserID.setVisible(True)
            self.algorithmConf_CB.setVisible(True)
            self.label_12.setVisible(True)
        else:

            self.publicKeyUserID.setCurrentIndex(0)
            self.algorithmConf_CB.setCurrentIndex(0)
            self.publicKeyUserID.setVisible(False)
            self.algorithmConf_CB.setVisible(False)
            self.label_12.setVisible(False)

    def rows_private_key_ring(self):
        keys = self.private_key_ring.get_private_key_ring().keys()
        return len(keys)

    def rows_public_key_ring(self):
        keys = self.public_key_ring.get_public_key_ring().keys()
        return len(keys)

    def populate_PrivateKeyRing(self):
        table_widget = self.PrivateKeyRing
        num_rows = self.rows_private_key_ring()
        num_cols = 8
        table_widget.setRowCount(num_rows)
        table_widget.setColumnCount(num_cols)
        private_key_ring = self.private_key_ring.get_private_key_ring()

        # columns: timestamp, key_id, public_key, encrypted_private_key, user_id

        try:
            row = 0
            for value in private_key_ring.values():
                timestamp = value.get_timestamp()
                key_id = value.get_key_id()
                public_key = value.get_public_key()
                encrypted_private_key = value.get_encrypted_private_key()
                user_email = value.get_user_email()

                table_widget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(timestamp)))
                table_widget.setItem(row, 1, QtWidgets.QTableWidgetItem(str(key_id)))
                table_widget.setItem(row, 2, QtWidgets.QTableWidgetItem(str(public_key)))
                table_widget.setItem(row, 3, QtWidgets.QTableWidgetItem(str(encrypted_private_key)))
                table_widget.setItem(row, 4, QtWidgets.QTableWidgetItem(str(user_email)))
                button1 = QtWidgets.QPushButton("Export")
                button1.setObjectName(str(key_id))
                button1.clicked.connect(self.export_key)
                table_widget.setCellWidget(row, 5, button1)

                button2 = QtWidgets.QPushButton("Delete")
                button2.setObjectName(str(key_id))
                button2.clicked.connect(self.remove_key_pair)
                table_widget.setCellWidget(row, 6, button2)

                button3 = QtWidgets.QPushButton("Decrypt PR")
                button3.setObjectName(str(key_id))
                button3.clicked.connect(self.decrypt_private_key)
                table_widget.setCellWidget(row, 7, button3)


                row += 1
                if row >= num_rows:
                    break
        except Exception as e:
            print(str(e))
            return

    def decrypt_private_key(self):
        button = app.sender()
        key_id = eval(button.objectName())

        privateKey = self.private_key_ring.get_row(key_id)
        encrypted_private_key = privateKey.get_encrypted_private_key()
        hash_user_password= privateKey.get_hash_user_password()
        user_inputed_password, ok = QInputDialog.getText(self, "Password", "Enter password for private key:")
        if ok:
            sha1 = hashlib.sha1()
            sha1.update(user_inputed_password.encode('utf-8'))
            hash_user_inputed_password = sha1.digest()
            hash_user_inputed_password=hash_user_inputed_password[:16]
            if hash_user_inputed_password==hash_user_password:



                cast128_cipher = CAST.new(hash_user_password, CAST.MODE_ECB)
                decrypted_private_key_padded = cast128_cipher.decrypt(encrypted_private_key)
                decrypted_private_key = Padding.unpad(decrypted_private_key_padded, cast128_cipher.block_size)
                print(str(decrypted_private_key))
                QtWidgets.QMessageBox.about(self, "Done",
                                            "Private key decrypted successfully!")


    def populate_PublicKeyRing(self):
        table_widget = self.publicKeyRing

        public_key_ring = self.public_key_ring.get_public_key_ring()
        num_rows = self.rows_public_key_ring()
        num_cols =6
        table_widget.setRowCount(num_rows)
        table_widget.setColumnCount(num_cols)

        try:
            row = 0
            for value in public_key_ring.values():

                timestamp = value.get_timestamp()
                key_id = value.get_key_id()
                public_key = value.get_public_key()
                user_email = value.get_user_email()

                table_widget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(timestamp)))
                table_widget.setItem(row, 1, QtWidgets.QTableWidgetItem(str(key_id)))
                table_widget.setItem(row, 2, QtWidgets.QTableWidgetItem(str(public_key)))
                table_widget.setItem(row, 3, QtWidgets.QTableWidgetItem(str(user_email)))
                button1 = QtWidgets.QPushButton("Export")
                button1.setObjectName(str(key_id))
                button1.clicked.connect(self.export_key)
                table_widget.setCellWidget(row, 4, button1)

                button2 = QtWidgets.QPushButton("Delete")
                button2.setObjectName(str(key_id))
                button2.clicked.connect(self.remove_key_pair)
                table_widget.setCellWidget(row, 5, button2)



                row += 1
                if row >= num_rows:
                    break
        except Exception as e:
            print(str(e))
            return

    def generate_key_pair(self, algorithm, key_size):
        if algorithm == "RSA":
            try:
                rand_function = Random.new().read
                key_pair = RSA.generate(key_size, rand_function)
                private_key_recipient = key_pair.export_key()
                public_key_recipient = key_pair.publickey().export_key()
                return [private_key_recipient, public_key_recipient]
            except Exception as e:
                QtWidgets.QMessageBox.about(self, "Error",
                                            "Greska prilikom generisanja RSA para kljuceva: " + str(e))
                return []
        if algorithm == "DSA":
            try:
                # rand_function = Random.new().read
                # key_pair = DSA.generate(key_size, rand_function)
                # private_key_recipient = key_pair.export_key()
                # public_key_recipient = key_pair.publickey().export_key()
                # return [private_key_recipient, public_key_recipient, key_pair]
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
                return [private_key, public_key]
            except Exception as e:
                QtWidgets.QMessageBox.about(self, "Error",
                                            "Greska prilikom generisanja DSA para kljuceva: " + str(e))
                return []
        if algorithm == "ElGamal":
            try:
                eg = ElGamal()
                eg.generate_elgamal_keypair(key_size)
                private_key = eg.get_elgamal_private_key()
                public_key = eg.get_elgamal_public_key()
                return [private_key, public_key]
            except Exception as e:
                QtWidgets.QMessageBox.about(self, "Error",
                                            "Greska prilikom generisanja ElGamal para kljuceva: " + str(e))
                return []

    def fill_form(self):
        name = self.name_LE.text()
        if not name:
            QtWidgets.QMessageBox.about(self, "Name required", "Hey ! Fill the name")
            return
        email = self.email_LE.text()
        if not email:
            QtWidgets.QMessageBox.about(self, "Email required", "Hey ! Fill the email")
            return
        alg = self.algorithm_CB.currentText()
        if not alg:
            QtWidgets.QMessageBox.about(self, "Algorithm required", "Hey ! Select algorithm")
            return
        keySize = self.keySize_CB.currentText()
        if not keySize:
            QtWidgets.QMessageBox.about(self, "Key Size required", "Hey ! Select key size")
            return
        password = self.password_LE.text()
        if not password:
            QtWidgets.QMessageBox.about(self, "Password required", "Hey ! Fill the password")
            return

        # popunjavanje Private Key Ring i Public Key Ring
        print("Name: " + name)
        print("Email: " + email)
        print("Alg: " + alg)
        print("KeySize: " + keySize)
        print("Password: " + password)

        # korisnik izabere lozinku kojom ce se sifrovati privatni kljucevi
        # izabrana lozinka = password

        # izracunati SHA-1, izracunava se 160bitni hash code od lozinke
        sha1 = hashlib.sha1()
        sha1.update(password.encode('utf-8'))
        hash_password = sha1.digest()
        print("Hashed password: " + str(hash_password))

        # na osnovu algoritma, koji je korisnik uneo, moramo da izvucemo par kreiranih kljuceva
        keySize = int(keySize)
        key_pair = self.generate_key_pair(algorithm=alg, key_size=keySize)
        private_key_salji=key_pair[0]
        public_key_salji=key_pair[1]
        private_key_str = key_pair[0]
        public_key_str = key_pair[1]
        key_p=None

        try:
            if alg == "RSA":
                public_key_str = public_key_str.splitlines()
                self.public_key = b'\n'.join(public_key_str[1:-1])

                private_key_str = private_key_str.splitlines()
                self.private_key = b'\n'.join(private_key_str[1:-1])


            elif alg == "ElGamal":
                # CHECK
                # ElGamal
                self.private_key = int(private_key_str)
                self.public_key = public_key_str
        except Exception as e:
            print("Greska 1")
            print(str(e))
            QtWidgets.QMessageBox.about(self, "Error", str(e))
            return



        print("Private key: " + str(self.private_key))
        print("Public key: " + str(self.public_key))

        # enkripcija privatnog kljuca hash vrednosti nase password-a sa CAST-128
        # key = hash password(128bits = 16bytes)

        hash_password = hash_password[:16]
        cast128_cipher = CAST.new(hash_password, CAST.MODE_ECB)






        try:
            if alg == "RSA" or alg == "DSA":
                private_key_padded = Padding.pad(private_key_salji, cast128_cipher.block_size)
            else:
                # ElGamal
                # izvrsiti enkripciju int value koristeci cast-128

                self.private_key = self.private_key.to_bytes((self.private_key.bit_length() + 7) // 8, 'big')
                private_key_padded = Padding.pad(self.private_key, cast128_cipher.block_size)
            try:

                encrypted_private_key = cast128_cipher.encrypt(private_key_padded)
                print("ENCRYPTED PRIVATE KEY: " + str(encrypted_private_key))
            except Exception as e:
                print("Greska 2")
                print(str(e))
                QtWidgets.QMessageBox.about(self, "Error", str(e))
                return
        except Exception as e:
            print("Greska 3")
            print(str(e))
            QtWidgets.QMessageBox.about(self, "Error", str(e))
            return

        if alg == "ElGamal":
            # javni kljuc ElGamal Ya, poslednja 64bita
            ya = int(self.public_key[3])
            ya_hex_number = hex(ya)[2:]
            key_id = int(ya_hex_number[-16:], 16)
        elif alg=="RSA":
            # poslednja 64bita bytes_string-a
            key_id = self.public_key[-8:]
        else:

            key_id = public_key_salji[-8:]
        ts = datetime.datetime.now()

        private_key_ring_elem = PrivateKeyRingElem(timestamp=ts,
                                                   key_id=key_id,
                                                   public_key=public_key_salji,
                                                   encrypted_private_key=encrypted_private_key,
                                                   user_email=email,
                                                   user_name=name,
                                                   hash_user_password=hash_password,
                                                   algorithm=alg,
                                                   key_size=keySize
                                                   )

        self.private_key_ring.private_key_ring_insert(key_id, private_key_ring_elem)

        print("PRIVATE KEY RING")
        self.private_key_ring.print()

        public_key_ring_elem = PublicKeyRingElem(timestamp=ts,
                                                 key_id=key_id,
                                                 public_key=public_key_salji,
                                                 user_email=email,
                                                 user_name=name,
                                                 hash_user_password=hash_password,
                                                 algorithm=alg,
                                                 key_size=keySize)

        self.public_key_ring.public_key_ring_insert(key_id, public_key_ring_elem)

        print("PUBLIC KEY RING")
        self.public_key_ring.print()
        if alg=="RSA":
            self.publicKeyUserID.addItem(str(key_id))
            self.privateKeyUserID.addItem(str(key_id))
        elif alg=="DSA":
            self.privateKeyUserID.addItem(str(key_id))
        else:
            self.publicKeyUserID.addItem(str(key_id))
        QtWidgets.QMessageBox.about(self, "Done", "Generated")

        self.populate_PublicKeyRing()
        self.populate_PrivateKeyRing()
        return

    def go_to_next_page(self):
        current_index=self.stackedWidget.currentIndex()
        next_index= (current_index+1)%self.stackedWidget.count()
        if next_index==2:
            self.nextButton.setEnabled(False)
        else:
            self.previousButton.setEnabled(True)
        self.stackedWidget.setCurrentIndex(next_index)

    def go_to_previous_page(self):
        current_index=self.stackedWidget.currentIndex()
        next_index= (current_index-1)%self.stackedWidget.count()
        if next_index==0:
            self.previousButton.setEnabled(False)
        else:
            self.nextButton.setEnabled(True)
        self.stackedWidget.setCurrentIndex(next_index)

    def sending(self,confidentiality, authentication, compression, conversion, filename, message, algorithmSim, keyIdPubConf, keyIdPrivAuth):
        if keyIdPrivAuth:
            privateKey = self.private_key_ring.get_row(eval(keyIdPrivAuth))
            algorithm = privateKey.get_algorithm()
            key_size = privateKey.get_key_size()
            encrypted_private_key = privateKey.get_encrypted_private_key()
            hash_user_password = privateKey.get_hash_user_password()
            user_inputed_password, ok = QInputDialog.getText(self, "Password", "Enter password for private key:")
            if ok:
                sha1 = hashlib.sha1()
                sha1.update(user_inputed_password.encode('utf-8'))
                hash_user_inputed_password = sha1.digest()
                hash_user_inputed_password = hash_user_inputed_password[:16]
                if hash_user_inputed_password == hash_user_password:
                    cast128_cipher = CAST.new(hash_user_password, CAST.MODE_ECB)
                    decrypted_private_key_padded = cast128_cipher.decrypt(encrypted_private_key)
                    decrypted_private_key = Padding.unpad(decrypted_private_key_padded, cast128_cipher.block_size)
                    print(str(decrypted_private_key))
                    private_key = decrypted_private_key

        if  not authentication and not confidentiality and not compression and not conversion:
            msg= str(authentication) + "\n" + str(confidentiality) + "\n" + str(compression) + "\n" + str(conversion) + "\n" + str(algorithmSim) + "\n" + filename + "\n" + str(
                datetime.datetime.now()) + "\n" + message
            return msg
        elif not authentication and not confidentiality and not compression and conversion:
            msg= filename + "\n" + str(datetime.datetime.now()) + "\n" + message
            serialized = pickle.dumps(msg)
            msg = str(authentication) + "\n" + str(confidentiality) + "\n" + str(compression) + "\n" + str(conversion) + "\n" + str(algorithmSim) + "\n" + str(base64.b64encode(serialized))
            return msg
        elif not authentication and not confidentiality and compression and not conversion:
            msg = filename + "\n" + str(datetime.datetime.now()) + "\n" + message

            msg = str(authentication) + "\n" + str(confidentiality) + "\n" + str(compression) + "\n" + str(conversion) + "\n" + str(algorithmSim) + "\n" + str(compress_data(msg))
            return msg
        elif not authentication and not confidentiality and compression and conversion:
            msg = filename + "\n" + str(datetime.datetime.now()) + "\n" + message
            first=compress_data(msg)
            serialized = pickle.dumps(first)
            second=base64.b64encode(serialized)
            msg = str(authentication) + "\n" + str(confidentiality) + "\n" + str(compression) + "\n" + str(conversion) + "\n" + str(algorithmSim) + "\n" + str(second)
            return msg

        if keyIdPubConf:
            publicKey=self.public_key_ring.get_row(eval(keyIdPubConf))
            public_key = publicKey.get_public_key()
            algorithm2 = publicKey.get_algorithm()
            key_size2 = publicKey.get_key_size()

        pgpAuth = PGPAuthentication()

        msg = Message(confidentiality=confidentiality, authentication=authentication, zip=compression,
                      radix64=conversion, filename=filename, timestampM=datetime.datetime.now(), data=message)

        message = msg.get_filename() + "\n" + str(msg.get_timestampM()) + "\n" + msg.get_data()
        if authentication:
            if algorithm == "RSA":
                pgpAuth.generate_rsa_keypair(key_size)
                message_digest = pgpAuth.encrypt_message_rsa(message, private_key)
                msg.set_timestamp(datetime.datetime.now())
                msg.set_keyIDSendersPublicKey(keyIdPrivAuth)
                msg.set_two_octets(message_digest[0:2])
                msg.set_message_digest(message_digest)


            else:

                message_digest=pgpAuth.encrypt_message_dsa(str(message), private_key)

                msg.set_timestamp(datetime.datetime.now())
                msg.set_keyIDSendersPublicKey(keyIdPrivAuth)
                msg.set_two_octets(message_digest[0:2])
                msg.set_message_digest(message_digest)
            message = str(datetime.datetime.now()) + "\n" + keyIdPrivAuth + "\n" + str(message_digest[0:2]) + "\n" + str(message_digest) + "\n" + msg.get_filename() + "\n" + str(
                msg.get_timestampM()) + "\n" + msg.get_data()

        if compression and not authentication:
            # compression of message

            message = compress_data(message)
            #nonce_ciphertext_tag = message
        elif compression and authentication:
            # compression of message and signature
            message = compress_data(message)
        if confidentiality:
            pgpConf = PGPConfidentiality()
            msg.set_keyIDRecipientPublicKey(keyIdPubConf)
            encrypted_with_session_key=None
            if algorithm2 == "RSA" and algorithmSim == "AES":
                pgpConf.generate_keys_rsa(public_key)
                for_sending = pgpConf.encrypt_message_rsa_aes(message, compression)
                strings = for_sending.split("@@@")
                session_key_cipher = strings[0]
                msg.set_session_key(session_key_cipher)
                encrypted_with_session_key = strings[1] + "@@@" + strings[2] + "@@@" + strings[3]

                #keyIDRecipientPublicKey = pgpConf.getPrivateKeyRSA()


            elif algorithm2 == "RSA" and algorithmSim == "3DES":
                pgpConf.generate_keys_rsa(public_key)
                for_sending = pgpConf.encrypt_message_rsa_3des(message, compression)
                strings = for_sending.split("@@@")
                session_key_cipher = strings[0]
                msg.set_session_key(session_key_cipher)
                encrypted_with_session_key = strings[1] + "@@@" + strings[2]
                #keyIDRecipientPublicKey = pgpConf.getPrivateKeyRSA()

            elif algorithm2 == "ElGamal" and algorithmSim == "AES":
                pgpConf.set_elgamal_key(public_key)

                session_key_cipher, encrypted_with_session_key = pgpConf.encrypt_message_elgamal_aes(message, compression)
                session_key_cipher=str(session_key_cipher)
                msg.set_session_key(session_key_cipher)
                #keyIDRecipientPublicKey = pgpConf.getKeysElGamal()

            elif algorithm2 == "ElGamal" and algorithmSim == "3DES":
                pgpConf.set_elgamal_key(public_key)
                session_key_cipher, encrypted_with_session_key = pgpConf.encrypt_message_elgamal_3des(message, compression)
                session_key_cipher=str(session_key_cipher)
                msg.set_session_key(session_key_cipher)
                #keyIDRecipientPublicKey = pgpConf.getKeysElGamal()

            message=msg.get_keyIDRecipientPublicKey()+"\n"+msg.get_session_key()+"\n"+str(encrypted_with_session_key)

        if conversion:
            serialized = pickle.dumps(message)
            msg = base64.b64encode(serialized)
            return str(authentication) + "\n" + str(confidentiality) + "\n" + str(compression) + "\n" + str(conversion) + "\n" + str(algorithmSim) + "\n" + str(msg)
        else:
            return str(authentication) + "\n" + str(confidentiality) + "\n" + str(compression) + "\n" + str(conversion) + "\n" + str(algorithmSim) + "\n" + str(message)

    def recieveMessage(self,file):
        with open(file,"r") as f:
            lines=f.readlines()
            message="".join(lines[5:])

        authentication=eval(lines[0])
        confidentiality=eval(lines[1])
        compression=eval(lines[2])
        conversion=eval(lines[3])
        algorithmSim=lines[4].replace("\n","")
        if not authentication and not confidentiality and not compression and not conversion:

            QtWidgets.QMessageBox.about(self, "Done", "Message recieved successfully: "+lines[7])
            return

        if conversion:
            decoded_data = base64.b64decode(eval(message))
            message = pickle.loads(decoded_data)

        if confidentiality:
            el=message.splitlines()

            ##############################################################################################
            self.key_id_LE.setText(el[0])

            privateKey = self.private_key_ring.get_row(eval(el[0]))
            public_key = privateKey.get_public_key()
            algorithm2 = privateKey.get_algorithm()
            encrypted_private_key = privateKey.get_encrypted_private_key()
            hash_user_password = privateKey.get_hash_user_password()
            user_inputed_password, ok = QInputDialog.getText(self, "Password", "Enter password for private key:")
            if ok:
                sha1 = hashlib.sha1()
                sha1.update(user_inputed_password.encode('utf-8'))
                hash_user_inputed_password = sha1.digest()
                hash_user_inputed_password = hash_user_inputed_password[:16]
                if hash_user_inputed_password == hash_user_password:
                    cast128_cipher = CAST.new(hash_user_password, CAST.MODE_ECB)
                    decrypted_private_key_padded = cast128_cipher.decrypt(encrypted_private_key)
                    decrypted_private_key = Padding.unpad(decrypted_private_key_padded, cast128_cipher.block_size)
                    print(str(decrypted_private_key))
                    private_key = decrypted_private_key


            pgpConf = PGPConfidentiality()
            if algorithm2 == "RSA" and algorithmSim == "AES":

                message = pgpConf.decrypt_message_rsa_aes(el[1],el[2], compression,
                                                                    private_key)


            elif algorithm2 == "RSA" and algorithmSim == "3DES":
                message = pgpConf.decrypt_message_rsa_3des(el[1],el[2], compression,
                                                                    private_key)

            elif algorithm2 == "ElGamal" and algorithmSim == "AES":

                message = pgpConf.decrypt_message_elgamal_aes(el[1],el[2], compression,
                                                                        public_key, private_key)

            elif algorithm2 == "ElGamal" and algorithmSim == "3DES":
                message = pgpConf.decrypt_message_elgamal_3des(el[1], el[2], compression,public_key, private_key)

        if compression:
            if not confidentiality and not conversion:
                message = decompress_data(eval(message))
            else:
                message = decompress_data(message)
        if authentication:
            pgpAuth = PGPAuthentication()
            final = message.splitlines()
            publicKey = self.public_key_ring.get_row(eval(final[1]))
            public_key = publicKey.get_public_key()
            name=publicKey.get_user_name()
            email=publicKey.get_user_email()
            algorithm = publicKey.get_algorithm()
            if compression:

                data = final[6].decode('utf-8')
            else:
                data = final[6]
            if algorithm == "RSA":



                if pgpAuth.decrypt_message_rsa(data, eval(final[3]), public_key):
                    self.original_message = data
                    QtWidgets.QMessageBox.about(self, "Done", "Signature is valid\nAuthor:\nName: "+name+"\nEmail: "+email)
            else:
                #DSA
                sigNew = eval(final[3])

                if pgpAuth.decrypt_message_dsa(data, sigNew, public_key):
                    self.original_message = data
                    QtWidgets.QMessageBox.about(self, "Done", "Signature is valid\nAuthor:\nName: "+name+"\nEmail: "+email)
        else:
            final = message.splitlines()
            if compression:
                self.original_message=final[2].decode('utf-8')
                QtWidgets.QMessageBox.about(self, "Done", "Message recieved successfully: "+ final[2].decode('utf-8'))
            else:
                self.original_message = final[2]
                QtWidgets.QMessageBox.about(self, "Done", "Message recieved successfully: "+final[2])

    def sendMessage(self):

        message = self.messageText.toPlainText()
        file=self.file_LE.text()
        if not message:
            QtWidgets.QMessageBox.about(self, "Message required", "Hey ! Fill the message")
            return
        if not file:
            QtWidgets.QMessageBox.about(self, "Filename required", "Hey ! Choose filename")
            return
        confidentiality = self.confidentiality_CB.isChecked()
        if confidentiality and self.publicKeyUserID.currentText()=='':
            QtWidgets.QMessageBox.about(self, "Key required", "Hey ! Select the public key")
            return
        if confidentiality and self.algorithmConf_CB.currentText()=='':
            QtWidgets.QMessageBox.about(self, "Algorithm required", "Hey ! Select the symmetric algorithm")
            return
        authentication = self.Authentication_CB.isChecked()
        if authentication and self.privateKeyUserID.currentText()=='':
            QtWidgets.QMessageBox.about(self, "Key required", "Hey ! Select the private key")
            return

        compression = self.compression_CB.isChecked()
        conversion = self.radix_CB.isChecked()
        if confidentiality and not authentication:
            keyIdPubConf=self.publicKeyUserID.currentText()
            algorithmSim = self.algorithmConf_CB.currentText()  # AES/3DES
            m= self.sending(confidentiality, authentication, compression, conversion, file, message, algorithmSim,keyIdPubConf,None)
        elif not confidentiality and authentication:
            keyIdPrivAuth=self.privateKeyUserID.currentText()
            m= self.sending(confidentiality, authentication, compression, conversion, file, message, None, None, keyIdPrivAuth)
        elif confidentiality and authentication:
            keyIdPubConf = self.publicKeyUserID.currentText()
            algorithmSim = self.algorithmConf_CB.currentText()  # AES/3DES
            keyIdPrivAuth = self.privateKeyUserID.currentText()
            m= self.sending(confidentiality, authentication, compression, conversion, file, message, algorithmSim,
                                keyIdPubConf, keyIdPrivAuth)
        else:
            m= self.sending(confidentiality, authentication, compression, conversion, file, message, None, None, None)
        with open(file,"w") as f:
            f.write(m)
        QtWidgets.QMessageBox.about(self, "Done", "Message sent successfully")
        #self.recieveMessage(file)


app=QtWidgets.QApplication([])
qt_app=MyMainWindow()
qt_app.show()
app.exec()

