from datetime import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
import zmq
import threading
from flask_mysqldb import MySQL
from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key, gen_keypair




class Blockchain:


    def create_genesis_block(self, mysql):
        the_time = datetime.now()

        block = {}
        block['index'] = 1
        block['prev_hash'] = '0000000000'
        block['nonce'] = 456
        block['data'] = 'This is the genesis block of skolo-online python blockchain'
        block['timestamp'] = the_time.strftime('%Y-%m-%d %H:%M:%S.%f')

        encoded_block = json.dumps(block, sort_keys = True).encode()
        new_hash = hashlib.sha256(encoded_block).hexdigest()
        block['hash'] = new_hash

        #Add genesis block to the blockchain
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO blockchain_chain(block, nonce, hash, prev_hash, timestamp, data) VALUES(%s, %s, %s, %s, %s, %s)",
        (block['index'], block['nonce'], block['hash'], block['prev_hash'], block['timestamp'], block['data']))
        mysql.connection.commit()

        cur.close()

        return block



    def mine_new_block(self, transactions, mysql):

        the_time = datetime.now()
        prev_hash = ''
        cur = mysql.connection.cursor()

        block = {}
        block['nonce'] = 456
        block['data'] = transactions
        block['timestamp'] = the_time.strftime('%Y-%m-%d %H:%M:%S.%f')

        result = cur.execute("SELECT * FROM blockchain_chain")
        chain = cur.fetchall()
        current_index = len(chain) + 1
        if result > 0 :
            length = len(chain)
            cur.execute("SELECT * from blockchain_chain WHERE block=%s", [length])
            last_block = cur.fetchone()
            prev_hash = last_block['hash']

        block['index'] = current_index
        block['prev_hash'] = prev_hash

        mining = False
        while mining is False:
            encoded_block = json.dumps(block, sort_keys = True).encode()
            new_hash = hashlib.sha256(encoded_block).hexdigest()

            if new_hash[:5] == '00009':
                mining = True
            else:
                block['nonce'] += 1

                encoded_block = json.dumps(block, sort_keys = True).encode()
                new_hash = hashlib.sha256(encoded_block).hexdigest()


        block['hash'] = new_hash

        #Add new block to the chain
        cur.execute("INSERT INTO blockchain_chain(block, nonce, hash, prev_hash, timestamp, data) VALUES(%s, %s, %s, %s, %s, %s)",
        (block['index'], block['nonce'], block['hash'], block['prev_hash'], block['timestamp'], json.dumps(block['data'])))
        mysql.connection.commit()

        cur.close()

        return block


    def add_transaction(self, public_key, new_transaction, signature, transaction_id, mysql):
        #Before we add a transaction - just check that it does not exist in the transaction pool already
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM blockchain_transactions")
        transactions = cur.fetchall()

        if result > 0:
            for transact in transactions:

                trans = json.loads(transact['transaction'])
                if trans['transaction_id'] == new_transaction['transaction_id']:
                    print('transaction {} already exists in the pool'.format(trans))
                    return

        #Add Transaction to Database
        string_trans = json.dumps(new_transaction, sort_keys = True).encode()
        string_signature = json.dumps(signature)

        cur.execute("INSERT INTO blockchain_transactions(public_key, signature, transaction_id, transaction) VALUES(%s, %s, %s, %s)", (public_key, string_signature, transaction_id, string_trans))
        mysql.connection.commit()

        cur.execute("SELECT * FROM blockchain_chain")
        chain = cur.fetchall()
        cur.close()

        return len(chain) + 1



    def check_valid_transactions(self, mysql):
        #Start by verifying all the transactions in the pool
        verified_transactions = []

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM blockchain_transactions")
        transactions = cur.fetchall()

        #We are going to verify all the transactions in the pool before we add them to the block .....
        #then clear the transaction pool by deleting all the transactions in the database ....
        if result > 0:
            for transaction in transactions:
                id = transaction['id']
                data = json.loads(transaction['transaction'])
                signature_string = transaction['signature']

                string_transaction = json.dumps(data, sort_keys = True).encode()

                signature = eval(signature_string)

                public, key2 = keys.get_public_keys_from_sig(signature, string_transaction, curve=curve.secp256k1, hashfunc=ecdsa.sha256)

                is_valid = ecdsa.verify(signature, string_transaction, public, curve.secp256k1, ecdsa.sha256)
                if is_valid is True:
                    verified_transactions.append(data)

        cur.close()
        return verified_transactions



    def proof_of_work(self, mysql):
        #Start by verifying all the transactions in the pool
        verified_transactions = []

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM blockchain_transactions")
        transactions = cur.fetchall()

        #We are going to verify all the transactions in the pool before we add them to the block .....
        #then clear the transaction pool by deleting all the transactions in the database ....
        if result > 0:
            for transaction in transactions:
                id = transaction['id']
                data = json.loads(transaction['transaction'])
                signature_string = transaction['signature']

                string_transaction = json.dumps(data, sort_keys = True).encode()

                signature = eval(signature_string)
                public, key2 = keys.get_public_keys_from_sig(signature, string_transaction, curve=curve.secp256k1, hashfunc=ecdsa.sha256)

                is_valid = ecdsa.verify(signature, string_transaction, public, curve.secp256k1, ecdsa.sha256)
                if is_valid is True:
                    verified_transactions.append(data)
                cur.execute("DELETE from blockchain_transactions WHERE id=%s", [id])
                mysql.connection.commit()


        #Now we add the transactions to the new block
        the_time = datetime.now()
        prev_hash = ''
$
        block = {}
        block['nonce'] = 456
        block['data'] = verified_transactions
        block['timestamp'] = the_time.strftime('%Y-%m-%d %H:%M:%S.%f')

        block_result = cur.execute("SELECT * FROM blockchain_chain")
        chain = cur.fetchall()
        current_index = len(chain) + 1
        if block_result > 0 :
            length = len(chain)
            cur.execute("SELECT * from blockchain_chain WHERE block=%s", [length])
            last_block = cur.fetchone()
            prev_hash = last_block['hash']

        block['index'] = current_index
        block['prev_hash'] = prev_hash

        mining = False
        while mining is False:
            encoded_block = json.dumps(block, sort_keys = True).encode()
            new_hash = hashlib.sha256(encoded_block).hexdigest()

            if new_hash[:5] == '00009':
                mining = True
            else:
                block['nonce'] += 1

                encoded_block = json.dumps(block, sort_keys = True).encode()
                new_hash = hashlib.sha256(encoded_block).hexdigest()


        block['hash'] = new_hash

        #Add new block to the chain
        cur.execute("INSERT INTO blockchain_chain(block, nonce, hash, prev_hash, timestamp, data) VALUES(%s, %s, %s, %s, %s, %s)",
        (block['index'], block['nonce'], block['hash'], block['prev_hash'], block['timestamp'], json.dumps(block['data'])))
        mysql.connection.commit()

        cur.close()

        return block



    def check_len_transactions(self, mysql):
        #Start by fetching all the current transactions from the database . . . .
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM blockchain_transactions")
        transactions = cur.fetchall()

        cur.close()

        if len(transactions) > 10:
            #We have more than 10 transactions in the pool
            return True
        else:
            return False


    def is_chain_valid(self, chain, mysql):
        first_block = chain[0]

        cur = mysql.connection.cursor()
        cur.execute("SELECT * from blockchain_chain WHERE id = 1")
        genesis_block = cur.fetchone()


        #Check that received chain has same Genesis block as our chain
        encoded_block_1 = json.dumps(first_block, sort_keys = True).encode()
        hash_1 = hashlib.sha256(encoded_block_1).hexdigest()

        encoded_block_2 = json.dumps(genesis_block, sort_keys = True).encode()
        hash_2 = hashlib.sha256(encoded_block_2).hexdigest()

        if not hash_1 == hash_2:
            print('validity failed comparing genesis blocks')
            return False

        cur.execute("SELECT * FROM blockchain_chain")
        myChain = cur.fetchall()


        #Now we check for the hash signature of every block in the chain - comparing it to our own . . . .
        block_index = 1
        while block_index < len(myChain):
            block = chain[block_index]
            our_block = myChain[block_index]

            encoded_block_1 = json.dumps(block, sort_keys = True).encode()
            hash_1 = hashlib.sha256(encoded_block_1).hexdigest()

            encoded_block_2 = json.dumps(our_block, sort_keys = True).encode()
            hash_2 = hashlib.sha256(encoded_block_2).hexdigest()


            if not hash_1 == hash_2:
                print('validity failed comparing #hash for block at index {}'.format(block_index))
                return False
            if not block['nonce'] == our_block['nonce']:
                print('validity failed comparing the nonce values and index {}'.format(block_index))
                return False

            previous_block = block
            block_index += 1

        cur.close()
        return True
