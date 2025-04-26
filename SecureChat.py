import socket
import threading
import atexit
import json
import time
import os
from datetime import datetime
from Crypto.Util.number import getPrime, getRandomRange
import hashlib
import pyDes
import random
from collections import OrderedDict

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        s.close()
        return "192.168.1.1"


def get_ip_subnet(ip):
    return ".".join(ip.split(".")[:-1])

def render_online_users(online_users):
    print("Online Users:")
    for i, (_, user) in enumerate(online_users.items()):
        if user["crypt_key"] is None:
            print(f"{i + 1}. {user['name']} (initializing...)")
        elif (user["unread_messages"] == 0):
            print(f"{i + 1}. {user['name']}")
        else:    
            print(f"{i + 1}. {user['name']} ({user['unread_messages']} unread messages)")


def send_json(ip, message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((ip, 40000))
            s.send(json.dumps(message).encode())
            s.close()
            return True
    except:
        return False    

def generate_safe_prime(bits=256):
    g = random.choice([2, 3, 5, 7])
    p = getPrime(bits)
    return g, p


username = input("Enter your name: ")
while username.strip() == "" or len(username) >= 128:
    print("Invalid username")
    username = input("Enter your name: ")




my_ip = get_ip()
broadcast_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
broadcast_server.bind(("0.0.0.0", 40000))

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((my_ip, 40000))
server.listen()

online_users = OrderedDict()
renderState = 1
active_user = "-1"
thread_lock = threading.Lock()


def close_servers():
    broadcast_server.close()
    server.close()
atexit.register(close_servers)

def update_user_key(ip, key):
    global renderState
    if ip in online_users.keys():
        online_users[ip]["crypt_key"] = key
        if renderState != 2 and renderState != 3:
            renderState = 1

def insert_user_key(ip, shared, private):
    global renderState
    if ip in online_users.keys():
        online_users[ip]["crypt_key"] = shared
        online_users[ip]["private_session_key"] = private
        if renderState != 2 and renderState != 3:
            renderState = 1
def send_init(ip):
    crypt_g, crypt_p = generate_safe_prime()
    crypt_private_session_key = getRandomRange(1, crypt_p - 1)
    public_key = pow(crypt_g, crypt_private_session_key, crypt_p)
    json_message = {"type": "INIT", "sender_name": username, "g": crypt_g, "p": crypt_p, "public_key": public_key}
    if send_json(ip, json_message):
        with thread_lock:
            online_users[ip]["private_session_key"] = crypt_private_session_key

def send_init_resp(ip, crypt_g, crypt_p, crypt_private_session_key):
    public_key = pow(crypt_g, crypt_private_session_key, crypt_p)
    json_message = {"type": "INIT_RESP", "sender_name": username, "g": crypt_g, "p": crypt_p, "public_key": public_key}
    if send_json(ip, json_message):
        with thread_lock:
            online_users[ip]["private_session_key"] = crypt_private_session_key


def serverThread():
    global renderState
    global active_user
    while True:
        client, address = server.accept()
        output = client.recv(1024).decode()
        client.close()
        if output:
            try:
                client_ip = address[0]
                message = output.strip()
                message = json.loads(message)
                message_type = message["type"].lower()
                if (message_type == "message"):
                    payload = message["payload"]
                    sender_name = message["sender_name"]

                    with thread_lock:
                        if client_ip in online_users.keys():
                            user = online_users[client_ip]
                            if user["crypt_key"] is not None:
                                payload = bytes.fromhex(payload)
                                payload = pyDes.triple_des(user["crypt_key"].ljust(24)).decrypt(payload, padmode=2)
                                evolved_crypt_key = hashlib.sha256(user["crypt_key"] + payload).digest()[:24]
                                user["crypt_key"] = evolved_crypt_key
                            user["messages"].append({"sender": sender_name, "message": payload, "timestamp": message["timestamp"]})
                            if renderState != 2 and renderState != 3:
                                user["unread_messages"] += 1
                                renderState = 1
                            elif active_user != "-1" and active_user == client_ip:
                                renderState = 3    
                            else:    
                                user["unread_messages"] += 1    
                            break         
                elif (message_type == "discover_resp"):
                    sender_name = message["responder_name"]
                    with thread_lock:
                        online_users[client_ip] = {"name": sender_name, "unread_messages": 0, "messages": [], "crypt_key": None}
                        if renderState == 0:
                            renderState = 1
                    send_init(client_ip)
                elif (message_type == "init"):
                    crypt_g = message["g"]
                    crypt_p = message["p"]
                    public_key = message["public_key"]
                    crypt_private_key = getRandomRange(1, crypt_p - 1)
                    shared_key = pow(public_key, crypt_private_key, crypt_p)
                    hash_key = hashlib.sha256(str(shared_key).encode()).digest()[:24]
                    with thread_lock:
                         insert_user_key(client_ip, hash_key, crypt_private_key)
                    send_init_resp(client_ip, crypt_g, crypt_p, crypt_private_key)
                elif (message_type == "init_resp"):
                    crypt_g = message["g"]
                    crypt_p = message["p"]
                    public_key = message["public_key"]
                    crypt_private_key = online_users[client_ip]["private_session_key"]
                    shared_key = pow(public_key, crypt_private_key, crypt_p)
                    hash_key = hashlib.sha256(str(shared_key).encode()).digest()[:24]
                    with thread_lock:
                        update_user_key(client_ip, hash_key)
                    
            except:
                pass

recieved_timestamps = set()

def broadcast_server_thread():
    global renderState
    while True:
        data, addr = broadcast_server.recvfrom(1024)
        try:
            client_ip = addr[0]
            if client_ip == my_ip:
                continue
            message = json.loads(data.decode().strip())
            if message["sequence_number"] in recieved_timestamps:
                continue
    
            recieved_timestamps.add(message["sequence_number"])
            with thread_lock:
                online_users[client_ip] = {"name": message["sender_name"], "unread_messages": 0, "messages": [], "crypt_key": None}
                send_json(client_ip, {"type": "DISCOVER_RESP", "responder_ip": my_ip, "responder_name": username})
                if renderState == 0:
                    renderState = 1
        except:
            pass
        


ip_subnet = get_ip_subnet(my_ip)
broadcast_ip = ip_subnet + ".255"

broadcastThread = threading.Thread(target=broadcast_server_thread, daemon=True)
broadcastThread.start()

server_Thread = threading.Thread(target=serverThread, daemon=True)
server_Thread.start()

print("Searching for users...")
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    discoverJson = json.dumps({"type": "DISCOVER_REQ", "sender_ip": my_ip, "sender_name": username, "sequence_number": (int)(time.time())}).encode()   
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(discoverJson, (broadcast_ip, 40000))
    s.sendto(discoverJson, (broadcast_ip, 40000))
    s.sendto(discoverJson, (broadcast_ip, 40000))
    s.close()


def renderThread():
    global renderState
    global active_user
    while True:
        with thread_lock:
            if renderState == 1:
                os.system('cls' if os.name == 'nt' else 'clear')
                render_online_users(online_users)
                print()
                if (len(online_users) != 0):
                    print("Enter user index to view chat or enter Q to exit the program: ")
                renderState = 0
            elif renderState == 3:
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"Chat with {online_users[active_user]['name']}:")
                for message in online_users[active_user]["messages"]:
                    print(f"{message['sender']}: {message['message']} ({datetime.fromtimestamp(int(message['timestamp'])).strftime('%d.%m.%Y %H:%M:%S')})")
                print()    
                print("Enter message or enter Q to go back to previous menu: ")    
                renderState = 2            
        time.sleep(0.3)




def inputThread():
    global renderState
    global active_user
    while True:
        userInput = input()
        with thread_lock:
            if renderState == 0 or renderState == 1:
                if userInput == "Q":
                    os._exit(0)
                if len(online_users) <= 0:
                    continue
                online_users_list = list(online_users.items())
                if (not userInput.isdigit()) or (int(userInput) < 1 or int(userInput) > len(online_users_list)):
                    print("Invalid user index")
                    continue
                active_user = online_users_list[int(userInput) - 1][0]
                if online_users[active_user]["crypt_key"] is None:
                    print("User is initializing...")
                    active_user = "-1"
                    continue
                online_users[active_user]["unread_messages"] = 0
                renderState = 3
            else:
                message = userInput
                if len(message) >= 128:
                    print("Message is too long")
                    continue
                if message == "Q":
                    active_user = "-1"
                    renderState = 1
                else:
                    encrypted_message = pyDes.triple_des(online_users[active_user]["crypt_key"].ljust(24)).encrypt(message, padmode=2)
                    encrypted_message = encrypted_message.hex()
                    res = send_json(active_user, {"type": "MESSAGE", "sender_name": username, "payload": encrypted_message, "timestamp": int(time.time())})
                    if res:
                        online_users[active_user]["messages"].append({"sender": username, "message": message, "timestamp": int(time.time())})
                        evolved_crypt_key = hashlib.sha256(online_users[active_user]["crypt_key"] + message.encode()).digest()[:24]
                        online_users[active_user]["crypt_key"] = evolved_crypt_key
                        renderState = 3
                    else:
                        print("Failed to send message")    
        time.sleep(0.5)        




input_Thread = threading.Thread(target=inputThread)
input_Thread.daemon = True
input_Thread.start()

time.sleep(1)
os.system('cls' if os.name == 'nt' else 'clear')

render_Thread = threading.Thread(target=renderThread)
render_Thread.daemon = True
render_Thread.start()

input_Thread.join()

