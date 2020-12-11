
from flask import Flask, render_template, request, jsonify
import config
from account import Account
from blockchain import Blockchain
from peertopeer import Peer2PeerServer
from flask_mysqldb import MySQL
import json
from fastecdsa import curve, ecdsa, keys, point
from fastecdsa.keys import export_key, import_key, gen_keypair
from datetime import datetime
from uuid import uuid4
import hashlib
import requests
from urllib.parse import urlparse
import zmq
import threading
import time



def page_not_found(e):
  return render_template('404.html'), 404


app = Flask(__name__)

app.config.from_object(config.config['development'])
app.register_error_handler(404, page_not_found)


mysql = MySQL(app)


#Initialise the imported classes
account = Account()
blockchain = Blockchain()
peerserver = Peer2PeerServer()


#Initialise ZMQ Context
context = zmq.Context()

#Set up the publishers
transaction_publisher = peerserver.bind_transaction_broadcast_port(context)
chain_publisher = peerserver.bind_chain_broadcast_port(context)

#Set up the subscribers
transaction_subscriber = context.socket(zmq.SUB)
chain_subscriber = context.socket(zmq.SUB)




@app.route('/')
def index():

    return render_template('index.html', **locals())

@app.route('/test')
def test():

    data = {
    "fullNames": 'Bertha Matshidiso Kgokong',
    "practiceNumber": '1234567890',
    "notes": 'I believe, we will make it to the moon and we will do it in this century'
    }

    private, public = import_key('/home/zatosh/keys/secp256k1.key')

    transaction = account.create_transaction(data)
    string_transaction = json.dumps(transaction, sort_keys = True).encode()
    signature = ecdsa.sign(string_transaction, private, curve=curve.secp256k1, hashfunc=ecdsa.sha256)


    ##-----------------------------------------


    #Assume we are now - publishing the transaction
    transaction['signature'] = json.dumps(signature)
    to_send = json.dumps(transaction, sort_keys = True)


    #Now Let us See of This code will work . . . .
    trans_result = to_send
    transaction1 = json.loads(trans_result)
    #Add the Transaction to the pool
    string_signature1 = transaction1['signature']
    signature1 = eval(string_signature1)

    transaction1.pop('signature')
    string_transaction1 = json.dumps(transaction1, sort_keys = True).encode()

    key1, key2 = keys.get_public_keys_from_sig(signature1, string_transaction1, curve=curve.secp256k1, hashfunc=ecdsa.sha256)

    is_valid = ecdsa.verify(signature1, string_transaction1, key1, curve.secp256k1, ecdsa.sha256)

    print('Just received transaction broadcast {}: and added it to transaction pool'.format(transaction1))


    return "<h3>If this is true, the signatures did match - or else. ---> {}</h3>".format(is_valid)



@app.route('/addtransaction', methods = ['POST'])
def add_transaction():
    data = {
    "fullNames": request.form['fullNames'],
    "practiceNumber": request.form['practiceNumber'],
    "notes": request.form['notes']
    }

    private, public = import_key('/home/zatosh/keys/secp256k1.key')


    transaction = account.create_transaction(data)
    string_transaction = json.dumps(transaction, sort_keys = True).encode()
    signature = ecdsa.sign(string_transaction, private, curve=curve.secp256k1, hashfunc=ecdsa.sha256)

    index = blockchain.add_transaction(public, transaction, signature, transaction['transaction_id'], mysql)
    is_valid = ecdsa.verify(signature, string_transaction, public, curve.secp256k1, ecdsa.sha256)


    #Publish the transaction on the network
    transaction_publish = transaction
    transaction_publish['signature'] = json.dumps(signature)
    peerserver.broadcast_transaction(transaction_publish, transaction_publisher)

    transaction_id = transaction['transaction_id']
    response = {'message': 'Transaction id: {} will be added to block {}'.format(transaction_id, index),
                'transaction_details': transaction, 'signature_valid': is_valid }
    return jsonify(response), 201


#Get the list of transactions
@app.route('/gettransactions', methods = ['GET'])
def get_transactions():

    #Get the Transactions
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM blockchain_transactions")
    transactions = cur.fetchall()

    response = {'transactions': transactions }

    cur.close()
    return jsonify(response), 200

@app.route('/get-chain', methods = ['GET'])
def get_chain():

    #Get the Transactions
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM blockchain_chain")
    chain = cur.fetchall()

    response = chain

    cur.close()
    return jsonify(response), 200




#Connecting new nodes - New nodes will hit this route to get connected
@app.route('/connect-node', methods = ['POST'])
def connect_node():
    data = request.get_json()
    node = data['node']

    #http://the-ip-address:PORT

    #Get the new chain
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM blockchain_chain")
    chain = cur.fetchall()

    #Get the Nodes - We need to send the IP addresses so this node can also subscribe to them .....
    cur.execute("SELECT * FROM blockchain_nodes")
    nodes = cur.fetchall()

    #We need to do a check that the node does not already exists in our database before we add it
    for x in nodes:
        parsed_x = urlparse(x)
        parsed_node = urlparse(node)
        if parsed_x.netloc == parsed_node.netloc:
            #This URL is already in our database
            print('This URL is already in our database')
            return 'FAILED: ALREADY IN DATABASE'


    #If the URL does not already exist - we can proceed with adding it to the database
    #Add the node to the database
    peerserver.add_peer(node, mysql)
    peerserver.add_node(node, mysql)

    #We then need to subscribe to this new node -
    peerserver.add_transaction_subscribe_socket(node, transaction_subscriber, '22344')
    peerserver.add_chain_subscribe_socket(node, chain_subscriber, '21344')

    #Send everyone a copy of the chain - so the new connection can have it.
    if result > 0:
        peerserver.broadcast_chain(chain, chain_publisher)

    response = { 'nodes': nodes }
    cur.close()
    return jsonify(response), 201




#Other Functions that the blockchain needs . . . . .
#Initialise the ALPHA Node
def initialiseAlphaNode():
    #Start by Creating the Genesis Block
    blockchain.create_genesis_block(mysql)

    #Then Set a timeline for mining new blocks - wait an hour, then check transactions - if they are more than 10 - mine a new block
    while True:
        #Get the Transactions
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM blockchain_transactions")
        transactions = cur.fetchall()


        if result > 0:
            #Check if we have more than 10 Transactions in the pool
            if len(transactions) > 10:
                block_response = blockchain.proof_of_work(mysql)

                cur.execute("SELECT * FROM blockchain_chain")
                chain = cur.fetchall()

                #broadcast the new chain
                peerserver.broadcast_chain(chain, chain_publisher)
                print('Just mined a block and broadcasted the new chain {}'.format(chain))


        cur.close()

        #wait for two minutes before checking again
        time.sleep(120)



#Connect Node Function - From the Connecting Nodes
def createBlockchainConnection():
    #Create a POST Request to the ALPHA NODE .....
    url = app.config['ALPHA_NODE'] + 'connect-node'
    data = {'node': app.config['THIS_NODE']}
    r = requests.post(url, json=data)
    response = json.loads(r.text)

    #Subscribe to the Alpha Node
    peerserver.add_transaction_subscribe_socket(app.config['ALPHA_NODE'], transaction_subscriber, '22344')
    peerserver.add_chain_subscribe_socket(app.config['ALPHA_NODE'], chain_subscriber, '21344')

    if len(response['nodes'])>0:
        #We already have more than one Node connected
        #Send Connections to all the nodes in the list
        for node in response['nodes']:
            requests.post("http://{}/connect-node".format(node), json=data)
            #Subscribe to all the nodes in the list
            peerserver.add_transaction_subscribe_socket("http://{}/".format(node), transaction_subscriber, '22344')
            peerserver.add_chain_subscribe_socket("http://{}/".format(node), chain_subscriber, '21344')

    while True:
        #Get the Transactions
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM blockchain_transactions")
        transactions = cur.fetchall()


        if result > 0:
            #Check if we have more than 10 Transactions in the pool
            if len(transactions) > 10:
                blockchain.proof_of_work(mysql)

                cur.execute("SELECT * FROM blockchain_chain")
                chain = cur.fetchall()

                #broadcast the new chain
                peerserver.broadcast_chain(chain, chain_publisher)
                print('Just mined a block and broadcasted the new chain {}'.format(chain))


        cur.close()

        #wait for two minutes before checking again
        time.sleep(app.config['WAIT_TIME'])



#When we receive a new Transaction
def awaiting_transaction_broadcast():
    while True:
        trans_result = transaction_subscriber.recv_json()
        transaction = json.loads(trans_result)
        if 'signature' in transaction:
            #Add the Transaction to the pool
            string_signature = transaction['signature']
            signature = eval(string_signature)

            transaction.pop('signature')
            string_transaction = json.dumps(transaction, sort_keys = True).encode()

            key1, key2 = keys.get_public_keys_from_sig(signature, string_transaction, curve=curve.secp256k1, hashfunc=ecdsa.sha256)

            blockchain.add_transaction(key1, transaction, signature, transaction['transaction_id'], mysql)
            print('Just received transaction broadcast {}: and added it to transaction pool'.format(transaction))


def awaiting_chain_broadcast():
    while True:
        chain_result = chain_subscriber.recv_json()
        new_chain = json.loads(chain_result)
        print('We just received a new chain \n {}'.format(new_chain))

        if not 'signature' in new_chain:
            #Get our chain from the database
            cur = mysql.connection.cursor()
            result = cur.execute("SELECT * FROM blockchain_chain")
            chain = cur.fetchall()

            if chain == []:
                #The chain table is empty ..... save this chain to our database
                for new_block in new_chain:
                    block = new_block['block']
                    nonce = new_block['nonce']
                    hash = new_block['hash']
                    prev_hash = new_block['prev_hash']
                    timestamp = new_block['timestamp']
                    data = new_block['data']

                    cur.execute("INSERT INTO blockchain_chain(block, nonce, hash, prev_hash, timestamp, data) VALUES(%s, %s, %s, %s, %s, %s)", (block, nonce, hash, prev_hash, timestamp, data))
                mysql.connection.commit()
                cur.close()
                pass
            else:
                cur.close()

                if len(new_chain) > len(chain):
                    #We already have a chain table in our database saved - we just need to confirm chain is valid
                    if blockchain.is_chain_valid(new_chain, mysql):

                        #The received chain is valid - genesis blocks match and all block hashes and nonces also match
                        new_transactions = new_chain[len(new_chain)-1]['data']
                        verified_transactions = []

                        for transaction in new_transactions:
                            id = transaction['id']
                            data = json.loads(transaction['transaction'])
                            signature_string = transaction['signature']

                            string_transaction = json.dumps(data, sort_keys = True).encode()

                            signature = eval(signature_string)

                            public, key2 = keys.get_public_keys_from_sig(signature, string_transaction, curve=curve.secp256k1, hashfunc=ecdsa.sha256)

                            is_transaction_valid = ecdsa.verify(signature, string_transaction, public, curve.secp256k1, ecdsa.sha256)
                            if is_transaction_valid:
                                verified_transactions.append(data)
                                print('Valid Transaction -> {}'.format(data))
                            else:
                                print('The following transaction is not valid, cannot accept this new chain: {}'.format(transaction))
                                pass

                        #Replace our chain with new chain - if chain is valid and all transactions in the last block are also valid
                        cur = mysql.connection.cursor()


                        #Start by deleting the current chain from database
                        cur.execute("DELETE from blockchain_chain")
                        mysql.connection.commit()
                        #We also need to delete everything from the transaction table - because the transactions have been mined in this block.
                        cur.execute("DELETE from blockchain_transactions")
                        mysql.connection.commit()

                        #then save new blockchain in to our database
                        for new_block in new_chain:
                            block = new_block['block']
                            nonce = new_block['nonce']
                            hash = new_block['hash']
                            prev_hash = new_block['prev_hash']
                            timestamp = new_block['timestamp']
                            data = new_block['data']

                            cur.execute("INSERT INTO blockchain_chain(block, nonce, hash, prev_hash, timestamp, data) VALUES(%s, %s, %s, %s, %s, %s)", (block, nonce, hash, prev_hash, timestamp, data))
                        mysql.connection.commit()
                        cur.close()


                    else:
                        #Received chain is not valid
                        print('Received chain is not valid --> DISCARD')
                        pass


                else:
                    print('Received chain is shorter than or equal to the chain we already have -- > DISCARD')
                    pass

        else:
            #This is a transaction - transaction function will handle . . . .
            pass




if __name__ == '__main__':

    #If you were not the Alpha node
    #t1 = threading.Thread(target=createBlockchainConnection, daemon=True)

    t1 = threading.Thread(target=initialiseAlphaNode, daemon=True)
    t2 = threading.Thread(target=awaiting_transaction_broadcast, daemon=True)
    t3 = threading.Thread(target=awaiting_chain_broadcast, daemon=True)

    t1.start()
    t2.start()
    t3.start()

    app.run(host='0.0.0.0', port='8888', debug=True)
