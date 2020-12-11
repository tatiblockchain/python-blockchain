from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key, gen_keypair
from datetime import datetime
from uuid import uuid4
import hashlib
import json


class Account:


    def generate_key_pair(self):
        pvt, pub = gen_keypair(curve.secp256k1)
        export_key(pvt, curve=curve.secp256k1, filepath='/home/zatosh/keys/secp256k1.key')
        export_key(pub, curve=curve.secp256k1, filepath='/home/zatosh/keys/secp256k1.pub')
        return True


    def generate_private_key(self):
        private_key = keys.gen_private_key(curve.secp256k1)
        return private_key

    def generate_public_key(self, private_key):
        public_key = keys.get_public_key(private_key, curve.secp256k1)
        return public_key

    def create_transaction(self, data):
        transaction_id = str(uuid4()).replace('-', '')
        timing = datetime.now()
        timestamp = timing.strftime('%Y-%m-%d %H:%M:%S.%f')


        transaction = {}
        transaction['transaction_id'] = transaction_id
        transaction['timestamp'] = timestamp
        transaction['data'] = data

        return transaction

    def get_signature(self, transaction, private):
        encoded_transaction = json.dumps(transaction, sort_keys = True).encode()
        signature = ecdsa.sign(encoded_transaction, private, curve.secp256k1, ecdsa.sha256)
        return signature
