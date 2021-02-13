import sys
import os
import socket
import selectors
import logging
import json
import datetime
sys.path.append(os.path.abspath('../cryptography/'))
import symmetriccrypt
import diffiehellman

#logger settings
#instantiate a logger object
logger = logging.getLogger('root')
#set logger level
logger.setLevel(logging.DEBUG)
#formatter definition
console_formatter = logging.Formatter("%(levelname)s:: %(filename)s: %(lineno)d: %(message)s")
file_formatter = logging.Formatter("%(levelname)s:  %(asctime)s: %(filename)s: %(lineno)d: %(message)s")
#console handler - write logs on terminal
#handler definition
console_handler = logging.StreamHandler()
#set handler level
console_handler.setLevel(logging.DEBUG)
#set handler formatter
console_handler.setFormatter(console_formatter)
#file handler - write logs into a file
#handler definition
file_handler = logging.FileHandler('logs.log')
#set handler level
file_handler.setLevel(logging.INFO)
#set handler formatter
file_handler.setFormatter(file_formatter)
#set handlers into logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)
####################################################################################################
"""
protocol
messages from client to server:
    - RDHP  - Received DH Paramets:     {"header": "RDHP", "data": "OK"}                        Client sends a confirmation that he received DH parameters
    - CDHN  - Client DH Public Mumber:  {"header": "CN", "data": client_dh_public_number}       Client sends his dh public number to server
    - CN    - Client Name:              {"header": "CN", "data": client_name}                   Client sends his name to server                  
    - NM    - New Message:              {"header": "CM", "data": client_message}                Client sends new message to add on chat               
messages from server to client:
    - DHP   - DH Parameters:            {"header": "CM", "data": dh_parameters}                 Server sends dh parameters to client
    - SDHN  - Server DH Public Number:  {"header": "CM", "data": server_dh_public_number}       Server sends his dh public number to server    
    - SM    - Server Messages:          {"header": "SM", "data": server_message}                Server sends to client informations about other participants
    - OM    - others message:           {"header": "OM", "data": "author:message"}              Server sends to client messages from other participants    
"""
def do_CDHN(conn, data, client_infos):
    #do dh handshake
    client_dh_public_number = data["data"]
    logger.debug("Got client public number")
    #calculate common secret
    common_secret = diffiehellman.dh_calculete_common_secret(client_infos["dh_private_key"], client_dh_public_number)
    #save common secret
    clients_information[conn]["common_secret"] = common_secret
    clients_information[conn]["dh_handshake"] = True
    logger.info("a common secret with {} has been established".format(client_infos["addr"]))
    #handshake is done
    #send chat informations to client
    #first client
    if len(clients_connection) == 1:
        data = "you are alone on server, wait other participants"
    #chat already has more clients
    else:
        #say to new client who already is connected
        clients_name = [infos["name"] for (client, infos) in clients_information.items() if client != conn]
        data = "welcome, now you are connected with: {}".format(" ".join(clients_name))
    response = {"header": symmetriccrypt.encrypt(client_infos["common_secret"], "SM", "AES-128", "CBC").decode(),
                "data": symmetriccrypt.encrypt(client_infos["common_secret"], data, "AES-128", "CBC").decode()}
    conn.send(json.dumps(response).encode())
    logger.debug("fineshed do_CDHN")
def do_CN(conn, data, client_infos):
    data["data"] = symmetriccrypt.decrypt(client_infos["common_secret"], data["data"].encode(), "AES-128", "CBC").decode()
    clients_information[conn]["name"] = data["data"]
    #introduces the new client to others
    sey_to_others = "now {} is connected".format(client_infos["name"])
    for participant in clients_connection:
        if participant == conn or not(clients_information[participant]["dh_handshake"]):
            continue
        response = {"header": symmetriccrypt.encrypt(clients_information[participant]["common_secret"], "SM", "AES-128", "CBC").decode(),
                    "data": symmetriccrypt.encrypt(clients_information[participant]["common_secret"], sey_to_others, "AES-128", "CBC").decode()}
        participant.send(json.dumps(response).encode())
    logger.debug("fineshed do_CN, client name is {}".format(data["data"]))
def do_NM(conn, data, client_infos):
    data["data"] = symmetriccrypt.decrypt(client_infos["common_secret"], data["data"].encode(), "AES-128", "CBC").decode()
    now = datetime.datetime.now()
    now = "{}:{}".format(now.hour, now.minute)
    data["data"] = "{};{};{}".format(client_infos["name"], data["data"],now)
    for participant in clients_connection:
        if participant == conn or not(clients_information[participant]["dh_handshake"]):
            continue
        response = {"header": symmetriccrypt.encrypt(clients_information[participant]["common_secret"], "OM", "AES-128", "CBC").decode(),
                    "data": symmetriccrypt.encrypt(clients_information[participant]["common_secret"], data["data"], "AES-128", "CBC").decode()}
        participant.send(json.dumps(response).encode())
    logger.debug("finished do_NM")
####################################################################################################

def read(conn, mask):
    data = conn.recv(1024)
    client_infos = clients_information[conn]
    if data:
        data = json.loads(data)
        #client has done dh shandshake
        if client_infos["dh_handshake"]:
            data["header"] = symmetriccrypt.decrypt(client_infos["common_secret"], data["header"].encode(), "AES-128", "CBC").decode()
            if data["header"] == "CN": #client name
                #receive client name
                do_CN(conn, data, client_infos)
            elif data["header"] == "NM": #new message
                do_NM(conn, data, client_infos)
        #client has not done the dh handshake yet
        else:
            #client confirm received dh parameters
            if data["header"] == "RDHP":
                #send my dh public numbers to client
                conn.send(json.dumps({"header": "SDHN", "data": client_infos["my_dh_public_number"]}).encode())
                logger.debug("sended dh public number to new client")
            #do dh handshake
            else:
                do_CDHN(conn, data, client_infos)
    #empty data closing client connection
    else:
        logger.info('closing {}'.format(client_infos["addr"]))
        response = "{} leave on chat".format(client_infos["name"])
        clients_connection.remove(conn)
        del clients_information[conn]
        sel.unregister(conn)
        conn.close()
        #inform others who leave
        for participant in clients_connection:
            if not(clients_information[participant]["dh_handshake"]):
                continue
            response = {"header": symmetriccrypt.encrypt(clients_information[participant]["common_secret"], "SM", "AES-128", "CBC").decode(),
                        "data": symmetriccrypt.encrypt(clients_information[participant]["common_secret"], response, "AES-128", "CBC").decode()}
            participant.send(json.dumps(response).encode())
       
####################################################################################################

def accept(sock, mask):
    conn, addr = sock.accept()  # Should be ready
    conn.setblocking(False)
    logger.info('Accepted connection from {}'.format(addr))
    #selector register conn
    sel.register(conn, selectors.EVENT_READ, read)
    #generate diffie hellman parametes
    dh_parameters = diffiehellman.dh_generate_parameters()
    #send dh parameters to client
    conn.send(json.dumps({"header": "DHP", "data": dh_parameters}).encode())
    logger.debug("sended dh parameters to new client")
    #generate private key
    dh_private_key = diffiehellman.dh_generate_private_key(dh_parameters)
    #generate my public numbers
    my_dh_public_number = diffiehellman.dh_generate_public_key(dh_private_key)
    #save client infos
    clients_connection.append(conn)
    clients_information[conn] = {"dh_handshake": False,
                                 "have_client_public_number": False,
                                 "dh_parameters": dh_parameters,
                                 "dh_private_key": dh_private_key,
                                 "my_dh_public_number": my_dh_public_number,
                                 "addr": addr,
                                 "name": "someone"}
    logger.debug("saved client informations")
####################################################################################################


#clients informations
clients_connection = []
clients_information = {}

#create socket
sock = socket.socket()
HOST = 'localhost'      # server Address  
PORT = 1235             # server port
sock.bind((HOST, PORT))
sock.listen(100)
sock.setblocking(False)
#create selector 
sel = selectors.DefaultSelector()
#selector register sock 
sel.register(sock, selectors.EVENT_READ, accept)

logger.info('Server started.. waiting for connections')
#loop
while True:
    events = sel.select()
    for key, mask in events:
        callback = key.data
        callback(key.fileobj, mask) 
