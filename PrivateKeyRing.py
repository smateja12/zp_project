

class PrivateKeyRingElem:
    def __init__(self, timestamp, key_id, public_key, encrypted_private_key,
                 user_email, user_name, hash_user_password, algorithm, key_size):
        self.timestamp = timestamp
        self.key_id = key_id  # unique
        self.public_key = public_key
        self.encrypted_private_key = encrypted_private_key
        self.user_email = user_email
        self.user_name = user_name
        self.hash_user_password = hash_user_password
        self.algorithm = algorithm  # algo za sifrovanje
        self.key_size = key_size


    def get_timestamp(self):
        return self.timestamp

    def set_timestamp(self, timestamp):
        self.timestamp = timestamp

    def get_key_id(self):
        return self.key_id

    def set_key_id(self, key_id):
        self.key_id = key_id

    def get_public_key(self):
        return self.public_key

    def set_public_key(self, public_key):
        self.public_key = public_key

    def get_encrypted_private_key(self):
        return self.encrypted_private_key

    def set_encrypted_private_key(self, encrypted_private_key):
        self.encrypted_private_key = encrypted_private_key


    def get_user_email(self):
        return self.user_email

    def set_user_email(self, user_email):
        self.user_email = user_email

    def get_user_name(self):
        return self.user_name

    def set_user_name(self, user_name):
        self.user_name = user_name

    def get_hash_user_password(self):
        return self.hash_user_password

    def set_hash_user_password(self, hash_user_password):
        self.hash_user_password = hash_user_password

    def get_algorithm(self):
        return self.algorithm

    def set_algorithm(self, algorithm):
        self.algorithm = algorithm

    def get_key_size(self):
        return self.key_size

    def set_key_size(self, key_size):
        self.key_size = key_size



class PrivateKeyRing:
    def __init__(self):
        self.private_key_ring = {}

    def private_key_ring_insert(self, key, value: PrivateKeyRingElem):
        # dodavanje privatnog kljuca za odredjeni par kljuceva
        #self.private_key_ring.setdefault(key, value)
        if key not in self.private_key_ring:
            self.private_key_ring[key]=value

    def private_key_ring_remove(self, key):
        # brisanje privatnog kljuca za odredjeni par kljuceva
        self.private_key_ring.pop(key, None)

    def get_private_key_ring(self):
        return self.private_key_ring

    def get_row(self, key):
        if key in self.private_key_ring:
            return self.private_key_ring.get(key)

    def print(self):
        for key, value in self.private_key_ring.items():
            print(f"Key: {key}")
            print(f"Value:")
            print(f"  Timestamp: {value.timestamp}")
            print(f"  Key ID: {value.key_id}")
            print(f"  Public Key: {value.public_key}")
            print(f"  Encrypted Private Key: {value.encrypted_private_key}")
            print(f"  User Email: {value.user_email}")
            print(f"  User Name: {value.user_name}")
            print(f"  Hashed User Password: {value.hash_user_password}")
            print(f"  Algorithm: {value.algorithm}")
            print(f"  Key Size: {value.key_size}")
            print("--------------------")