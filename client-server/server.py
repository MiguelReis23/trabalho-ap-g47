#!/usr/bin/python3

import re
from ssl import _Cipher
import sys
import socket
import select
import json
import base64
import csv
import random
from unittest import result

from aiohttp import request
from common_comm import send_dict, recv_dict, sendrecv_dict

from Crypto.Cipher import AES

# Dicionário com a informação relativa aos clientes
users = {}

# return the client_id of a socket or None


def find_client_id(client_sock):
    for client_id in users:
        if users[client_id]["socket"] == client_sock:
            return client_id
    return None


# Função para encriptar valores a enviar em formato json com codificação base64
# return int data encrypted in a 16 bytes binary string and coded base64
def encrypt_intvalue(client_id, data):
    cipherkey= users[client_id]["cipher"]
    if cipherkey is None or not cipherkey: return None
    
    cipher = AES.new(cipherkey, AES.MODE_ECB)
    dataenctypted= cipher.encrypt(bytes("%16d"%(data), "utf-8"))
    dataenctyptedtosend= base64.b64encode(dataenctypted)
    return str(dataenctyptedtosend, "utf-8")


# Função para desencriptar valores recebidos em formato json com codificação base64
# return int data decrypted from a 16 bytes binary string and coded base64
def decrypt_intvalue(client_id, data):
    cipherkey= users[client_id]["cipher"]
    if cipherkey is None or not cipherkey: return None
    
    cipher = AES.new(cipherkey, AES.MODE_ECB)
    datadecoded= base64.b64encode(data)
    datadecrypted= cipher.decrypt(bytes(datadecoded))
    
    return int(str(datadecrypted, "utf-8"))


# Incomming message structure:
# { op = "START", client_id, [cipher] }
# { op = "QUIT" }
# { op = "NUMBER", number }
# { op = "STOP" }
#
# Outcomming message structure:
# { op = "START", status }
# { op = "QUIT" , status }
# { op = "NUMBER", status }
# { op = "STOP", status, min, max }
def operation(request):
    if request["op"] == "START":
        return "START"
    elif request["op"] == "QUIT":
        return "QUIT"
    elif request["op"] == "NUMBER":
        return "NUMBER"
    elif request["op"] == "STOP":
        return "STOP"

#
# Suporte de descodificação da operação pretendida pelo cliente
#


def new_msg(client_sock):
    msg = recv_dict(client_sock)
    if not "op" in msg: return False

    msg_op=msg["op"]

    if msg_op == "START":
        result = new_client(client_sock, msg)
    elif msg_op == "QUIT":
        result = quit_client(client_sock, msg)
    elif msg_op == "NUMBER":
        result = number_client(client_sock, msg)
    elif msg_op == "STOP":
        result = stop_client(client_sock, msg)
        
    send_dict(client_sock, result)
    
    return None
# read the client request
# detect the operation requested by the client
# execute the operation and obtain the response (consider also operations not available)
# send the response to the client


#
# Suporte da criação de um novo jogador - operação START
#
def new_client(client_sock, request):
    if not "client_id" in request:
        return {"op": request["op"], "status": False,"error":"client_id not found"}
    if not "cipher" in request:
        return {"op": request["op"], "status": False,"error":"cipher not found"}
    
    client_id= request["client_id"]
    cipher= request["cipher"]
    
    if  cipher: cipherkey = base64.b64decode(cipher)
    else: cipherkey= None
    
    if client_id in users: return {"op": request["op"], "status": False,"error":"client_id already exists"}
    
    users[client_id]= {"socket": client_sock, "cipher": cipherkey, "numbers": []}
    return {"op": request["op"], "status": True}
       
        

# detect the client in the request
# verify the appropriate conditions for executing this operation
# process the client in the dictionary
# return response message with or without error message


#
# Suporte da eliminação de um cliente
#
def clean_client(client_sock):
    client_id = find_client_id(client_sock)
    if client_id in users:
        del users[client_id]
    return None
# obtain the client_id from his socket and delete from the dictionary


#
# Suporte do pedido de desistência de um cliente - operação QUIT
#
def quit_client(client_sock, request): 
  client_id = find_client_id(client_sock)
  if not client_id: return {"op": request["op"], "status": False,"error":"client_id not found"}
  
  del users[client_id]
  return {"op": request["op"], "status": True}

# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# process the report file with the QUIT result
# eliminate client from dictionary
# return response message with or without error message


#
# Suporte da criação de um ficheiro csv com o respectivo cabeçalho
#
def create_file():
    file = open("report.csv", "w")
    writer = csv.DictWriter(file, fieldnames=["client_id", "numbers", "minimum", "maximum"])
    writer.writeheader()
    file.close()
    return None
# create report csv file with header


#
# Suporte da actualização de um ficheiro csv com a informação do cliente e resultado
#
def update_file(client_id, result):
    file = open("report.csv", "a")
    writer= csv.DictWriter(file, fieldnames=["client_id", "numbers", "minimum", "maximum"])
    writer.writerow({"client_id": client_id, "numbers": len(result["numbers"]), "minimum": result["minimum"], "maximum": result["maximum"]})
    return None
# update report csv file with the result from the client


#
# Suporte do processamento do número de um cliente - operação NUMBER
#
def number_client(client_sock, request):
    client_id = find_client_id(client_sock)
    if not client_id: return {"op": request["op"], "status": False,"error":"client_id not found"}
    if not "number" in request: return {"op": request["op"], "status": False,"error":"number not found"}
    number= request["number"]
    number= decrypt_intvalue(client_id, number)
    
    users[client_id]["numbers"].append(number)
    return {"op": request["op"], "status": True}
    return None
# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# return response message with or without error message


#
# Suporte do pedido de terminação de um cliente - operação STOP
#
def stop_client(client_sock, request):
    client_id= find_client_id(client_sock)
    
    if not client_id: return {"op": request["op"], "status": False,"error":"client_id not found"}
    
    numbers= users[client_id]["numbers"]
    
    if len(numbers)==0: return {"op": request["op"], "status": False,"error":"no numbers found"}
    
    minNumber= min(numbers)
    maxNumber= max(numbers)
    
    result= {"numbers": numbers, "minimum": minNumber, "maximum": maxNumber}
    update_file(client_id, result)
    
    del users[client_id]
    return {"op": request["op"], "status": True, "minimum": minNumber, "maximum": maxNumber}

# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# process the report file with the result
# eliminate client from dictionary
# return response message with result or error message


def main():
    # validate the number of arguments and eventually print error message and exit with error
    # verify type of of arguments and eventually print error message and exit with error
    if len(sys.argv) < 2:
        print("Usage: python3 {} <port>".format(sys.argv[0]))
        sys.exit(1)
    
    port = sys.argv[1]
    
    if not port.isdigit():
        print("Port must be a number")
        sys.exit(1)
    else:
        port=int(port)
    

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", port))
    server_socket.listen(10)

    clients = []
    create_file()

    while True:
        try:
            available = select.select([server_socket] + clients, [], [])[0]
        except ValueError:
            # Sockets may have been closed, check for that
            for client_sock in clients:
                if client_sock.fileno() == -1: client_sock.remove(client)  # closed
            continue  # Reiterate select

        for client_sock in available:
            # New client?
            if client_sock is server_socket:
                newclient, addr = server_socket.accept()
                clients.append(newclient)
            # Or an existing client
            else:
                # See if client sent a message
                if len(client_sock.recv(1, socket.MSG_PEEK)) != 0:
                    # client socket has a message
                    # print ("server" + str (client_sock))
                    new_msg(client_sock)
                else:  # Or just disconnected
                    clients.remove(client_sock)
                    clean_client(client_sock)
                    client_sock.close()
                    break  # Reiterate select


if __name__ == "__main__":
    main()
