import random
from Crypto.Util.number import getStrongPrime
import sympy

# ElGamal
class ElGamal:

    def __init__(self):
        self.private_key_recipient = None
        self.public_key_recipient = None

    def get_elgamal_private_key(self):
        return self.private_key_recipient

    def get_elgamal_public_key(self):
        return self.public_key_recipient

    def generate_elgamal_keypair(self, key_size):
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
        
#def rand_bytes(n):
#    return number.getRandomNBitInteger(n).to_bytes((n + 7) // 8, byteorder='big')
#bits = 1024
#random_bytes = rand_bytes(bits)
#print(random_bytes)
#elgamal_key = ElGamal.generate(bits, randfunc=lambda n: random_bytes)
