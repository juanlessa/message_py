import sys
import os
import selectors
import socket
import threading
import json
from datetime import datetime
#cryptography methods
sys.path.append(os.path.abspath('../cryptography'))
import symmetriccrypt
import diffiehellman
#kivy classes to build interface
from kivy.uix.boxlayout import BoxLayout
from kivy.app import App
from kivy.lang import Builder
from kivy.config import Config

#load kvlang interface
Builder.load_file("chat.kv")
#wimdow size
from kivy.config import Config
Config.set('graphics', 'width', '480')
Config.set('graphics', 'height', '640')
#interface
class Servernots(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class Mymessage(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class Message(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class MessageWithoutAuthor(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class ChatPage(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.lastMessage_author = ""

    def btn_send_clicked(self, **kwargs):
        kinput = self.ids.keyboard_inputs.text
        if kinput != "":
            message = Mymessage()
            message.ids.mes.text = kinput
            message.ids.hour.text = "{}:{}".format(datetime.now().hour, datetime.now().minute)
            self.ids.messagesbox.add_widget(message)
            self.ids.keyboard_inputs.text = ""
            self.lastMessage_author = my_name
            #send message to server
            response = {"header": symmetriccrypt.encrypt(server_connection["common_secret"], "NM", "AES-128", "CBC").decode(),
                        "data": symmetriccrypt.encrypt(server_connection["common_secret"], kinput, "AES-128", "CBC").decode()}
            sock.send(json.dumps(response).encode())
    def receive_chat_participants_message(self, received_message, **kwargs):

        if self.lastMessage_author == received_message[0]:
            message = MessageWithoutAuthor()
        else:
            message = Message()
            message.ids.author.text = received_message[0] #author name
            self.lastMessage_author = received_message[0]
        message.ids.mes.text = received_message[1] #message content
        message.ids.hour.text = received_message[2] #hour
        self.ids.messagesbox.add_widget(message)
    def receive_server_nofication(self, notification, **kwargs):
        message = Servernots()
        message.ids.mes.text = notification
        self.ids.messagesbox.add_widget(message)

class MainApp(App):
    def build(self):
        self.chatpage = ChatPage()
        return self.chatpage
####################################################################################################

#client server comunication protocol
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
def do_DHP(conn, data):
    conn.send(json.dumps({"header": "RDHP", "data": "OK"}).encode())
    #receeive diffie hellman parametes from server
    data = json.loads(data)
    dh_parameters = data["data"]
    #generate private key
    dh_private_key = diffiehellman.dh_generate_private_key(dh_parameters)
    #generate my public number
    my_dh_public_number = diffiehellman.dh_generate_public_key(dh_private_key)
    #send my dh public numbers to server
    conn.send(json.dumps({"header": "CDHN", "data": my_dh_public_number}).encode())       
    #save dh informations
    server_connection["dh_parameters"] = dh_parameters
    server_connection["dh_private_key"] = dh_private_key
    server_connection["my_dh_public_number"] = my_dh_public_number
    server_connection["have_dh_parameters"] = True
def do_SDHN(conn, data):
    #receive server public numbers
    data = json.loads(data)
    server_dh_public_number = data["data"]
    #calculate common secret
    common_secret = diffiehellman.dh_calculete_common_secret(server_connection["dh_private_key"], server_dh_public_number)
    server_connection["server_dh_public_number"] = server_dh_public_number
    server_connection["common_secret"] = common_secret
    server_connection["dh_handshake"] = True
    #send my name to server
    response = {"header": symmetriccrypt.encrypt(server_connection["common_secret"], "CN","AES-128", "CBC").decode(),
                "data": symmetriccrypt.encrypt(server_connection["common_secret"], my_name, "AES-128", "CBC").decode()}
    conn.send(json.dumps(response).encode())
def do_SM(conn, data):
    data = symmetriccrypt.decrypt(server_connection["common_secret"], data["data"].encode(), "AES-128", "CBC").decode()
    window.chatpage.receive_server_nofication(data)
def do_OM(conn, data):
    data = symmetriccrypt.decrypt(server_connection["common_secret"], data["data"].encode(), "AES-128", "CBC").decode()
    data = data.split(";")
    window.chatpage.receive_chat_participants_message(data)
####################################################################################################

#selector function
def server_message_received(conn):
    data = conn.recv(1024)
    #client has done dh shandshake
    if server_connection["dh_handshake"]:
        data = json.loads(data)
        data["header"] = symmetriccrypt.decrypt(server_connection["common_secret"], data["header"].encode(), "AES-128", "CBC").decode()
        #message chat settings
        if data["header"] == "SM":
            do_SM(conn, data)
        #chat messages
        elif data["header"] == "OM":
            do_OM(conn, data)
    #this client has not done the dh handshake yet
    else:
        if server_connection["have_dh_parameters"]:
            #receive server dh public numbers
            do_SDHN(conn, data)
        else:
            #receive dh parameters from server
            do_DHP(conn, data)
####################################################################################################

#thread
def thread_listen_connection(sock, selector):
    #selector register socket
    selector.register(sock, selectors.EVENT_READ, server_message_received)
    #loop
    while True:
        events = selector.select()  # events = list of tuples
        lock.acquire()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj)   # key.fileobj = sock
        lock.release()
####################################################################################################

server_connection = {"dh_handshake": False, "have_dh_parameters": False}
if __name__ == "__main__":
    #my name
    my_name = input("whats your name: ")
    #create selector
    selector = selectors.DefaultSelector()
    #create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    HOST = 'localhost'      # server Address  
    PORT = 1235             # server port
    #connect at server
    sock.connect((HOST, PORT))
    #create thread 
    thread = threading.Thread(target=thread_listen_connection, args=[sock, selector], daemon=True, name="ListenServerConnectionsThread")
    lock = threading.Lock()
    #load imterface
    window = MainApp()
    #start thread
    thread.start()
    #application takes control of the MainThread
    window.run()
