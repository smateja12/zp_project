

# struktura Poruke
class Message:
    def __init__(self, confidentiality, authentication, zip, radix64, filename, timestampM, data):
        # session key component
        self.confidentiality = confidentiality
        self.authentication = authentication
        self.zip = zip
        self.radix64 = radix64

        self.keyIDRecipientPublicKey = None
        self.session_key = None

        # signature
        self.timestamp = None
        self.keyIDSendersPublicKey = None
        self.two_octets = None
        self.message_digest = None

        # message komponenta
        self.filename = filename
        self.timestampM = timestampM
        self.data = data

    def set_keyIDRecipientPublicKey(self, keyIDRecipientPublicKey):
        self.keyIDRecipientPublicKey = keyIDRecipientPublicKey

    def set_session_key(self, session_key):
        self.session_key = session_key

    def set_timestamp(self, timestamp):
        self.timestamp = timestamp

    def set_keyIDSendersPublicKey(self, keyIDSendersPublicKey):
        self.keyIDSendersPublicKey = keyIDSendersPublicKey

    def set_two_octets(self, two_octets):
        self.two_octets = two_octets

    def set_message_digest(self, message_digest):
        self.message_digest = message_digest

    # getters
    def get_confidentiality(self):
        return self.confidentiality

    def get_authentication(self):
        return self.authentication

    def get_zip(self):
        return self.zip

    def get_radix64(self):
        return self.radix64

    def get_keyIDRecipientPublicKey(self):
        return self.keyIDRecipientPublicKey

    def get_session_key(self):
        return self.session_key

    def get_timestamp(self):
        return self.timestamp

    def get_keyIDSendersPublicKey(self):
        return self.keyIDSendersPublicKey

    def get_two_octets(self):
        return self.two_octets

    def get_message_digest(self):
        return self.message_digest

    def get_filename(self):
        return self.filename

    def get_timestampM(self):
        return self.timestampM

    def get_data(self):
        return self.data

