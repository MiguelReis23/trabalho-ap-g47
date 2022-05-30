#!/usr/bin/python3

import sys
import socket
import select
import json
import base64
import csv
import random
import os
from common_comm import send_dict, recv_dict, sendrecv_dict
from Crypto.Cipher import AES

# Dicionário com a informação relativa aos clientes
users = {}

# return the client_id of a socket or None

#find the client_id if it exists
def find_client_id(client_sock):
	for client_id in users:
		if users[client_id]["socket"] == client_sock:
			return client_id
	return None


# Função para encriptar valores a enviar em formato json com codificação base64
# return int data encrypted in a 16 bytes binary string and coded base64

def encrypt_intvalue(client_id, data):
	cipherkey= users[client_id]["cipher"] #check if the user has a cipher 
	if cipherkey is None or not cipherkey: return data
	#if the user has a cipher, encrypt the data
	cipher = AES.new(cipherkey, AES.MODE_ECB)
	dataencrypted= cipher.encrypt(bytes("%16d"%(data), "utf8"))
	dataencryptedtosend= base64.b64encode(dataencrypted)
	return str(dataencryptedtosend, "utf8")


# Função para desencriptar valores recebidos em formato json com codificação base64
# return int data decrypted from a 16 bytes binary string and coded base64
def decrypt_intvalue(client_id, data):
	cipherkey= users[client_id]["cipher"]#check if the user has a cipher
	if cipherkey is None or not cipherkey: return data
	#if the user has a cipher, decrypt the data
	cipher = AES.new(cipherkey, AES.MODE_ECB)
	datadecoded= base64.b64decode(data)
	datadecrypted= cipher.decrypt(datadecoded)
	return int(str(datadecrypted, "utf8"))


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

#function to handle the incoming messages
def operation(request):
	if request["op"] == "START":
		return "START"
	elif request["op"] == "QUIT":
		return "QUIT"
	elif request["op"] == "NUMBER":
		return "NUMBER"
	elif request["op"] == "STOP":
		return "STOP"


# Suporte de descodificação da operação pretendida pelo cliente

#from input run the functions
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
		result = stop_client(client_sock)
		
	send_dict(client_sock, result)
	
	return None
# read the client request
# detect the operation requested by the client
# execute the operation and obtain the response (consider also operations not available)
# send the response to the client



# Suporte da criação de um novo jogador - operação START

def new_client(client_sock, request):
	if not "client_id" in request: #check if the client_id is in the request
		return {"op": "START", "status": False,"error":"client_id not found"}
	if not "cipher" in request: #check if the cipher is in the request
		return {"op": "START", "status": False,"error":"cipher not found"}
	
	client_id= request["client_id"]
	cipher= request["cipher"]
	
	
	if  cipher: cipherkey = base64.b64decode(cipher) 
	else: cipherkey= None
 
	#check if the client_id is already in the dictionary
	if client_id in users: return {"op": "START", "status": False,"error":"client_id already exists"}
	
	users[client_id]= {"socket": client_sock, "cipher": cipherkey, "numbers": []}#add the client to the dictionary
	print("SERVER - Client {} conected".format(client_id))
	return {"op": "START", "status": True}

	   
		

# detect the client in the request
# verify the appropriate conditions for executing this operation
# process the client in the dictionary
# return response message with or without error message


#
# Suporte da eliminação de um cliente
#

def clean_client(client_sock):
	client_id = find_client_id(client_sock) #find the client_id
	if client_id in users: #check if the client_id is in the dictionary
		del users[client_id] #delete the client from the dictionary
	return None
# obtain the client_id from his socket and delete from the dictionary


#
# Suporte do pedido de desistência de um cliente - operação QUIT
#

def quit_client(client_sock, request): 
  client_id = find_client_id(client_sock)#find the client_id
  if not client_id: return {"op": "QUIT", "status": False,"error":"client_id not found"} #return error if the client_id is not in the dictionary
  
  del users[client_id] #delete the client from the dictionary
  print("SERVER - Client {} gave up on connection".format(client_id)) #print the quit message
  return {"op": "QUIT", "status": True}

# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# process the report file with the QUIT result
# eliminate client from dictionary
# return response message with or without error message


#
# Suporte da criação de um ficheiro csv com o respectivo cabeçalho
#
def create_file():
	if not os.path.isfile("report.csv"): #check if the file report.csv exists
		file = open("report.csv", "w")
		writer = csv.DictWriter(file, fieldnames=["client_id", "numbers", "minimum", "maximum"]) #format report.csv header
		writer.writeheader() #write the header
		file.close()
	return None
# create report csv file with header


#
# Suporte da actualização de um ficheiro csv com a informação do cliente e resultado
#
def update_file(client_id, result):
	file = open("report.csv", "a") #open the file in append mode
	writer= csv.DictWriter(file, fieldnames=["client_id", "numbers", "minimum", "maximum"]) #format report.csv header
	writer.writerow({"client_id": client_id, "numbers": len(result["numbers"]), "minimum": result["minimum"], "maximum": result["maximum"]}) #write the row of the client
	return None
# update report csv file with the result from the client


#
# Suporte do processamento do número de um cliente - operação NUMBER
#
def number_client(client_sock, request):
	client_id = find_client_id(client_sock) #find the client_id
	if not client_id: return {"op": "NUMBER", "status": False,"error":"client_id not found"} #return error if the client_id is not in the dictionary
	if not "number" in request: return {"op": "NUMBER", "status": False,"error":"number not found"} #return error if the number is not in the request
	number= request["number"] 
	number= decrypt_intvalue(client_id, number) #decrypt the number
	users[client_id]["numbers"].append(number) #add the number to the client
	print("SERVER - Client {} sent number {}".format(client_id, number)) #print the number sent by the client
	return {"op": "NUMBER", "status": True}
	
# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# return response message with or without error message


#
# Suporte do pedido de terminação de um cliente - operação STOP
#
def stop_client(client_sock):
	client_id= find_client_id(client_sock) #find the client_id
	
	if not client_id: return {"op": "STOP", "status": False,"error":"client_id not found"} #return error if the client_id is not in the dictionary
	
	numbers= users[client_id]["numbers"] #get the numbers from the client
	
	if len(numbers)==0: return {"op": "STOP", "status": False,"error":"no numbers found"} #return error if the client has not sent any number
	
	minNumber= min(numbers) #get the minimum number
	maxNumber= max(numbers) #get the maximum number
	
	result= {"numbers": numbers, "minimum": minNumber, "maximum": maxNumber} #create the result
	update_file(client_id, result) #update the report file
	
	del users[client_id] #delete the client from the dictionary
	print("SERVER - Client {} disconnected.".format(client_id))
	print("SERVER - Results: {} numbers sent, minimum: {}, maximum: {}".format(len(numbers), minNumber, maxNumber)) #print the results
	
	return {"op": "STOP", "status": True, "minimum": minNumber, "maximum": maxNumber}

# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# process the report file with the result
# eliminate client from dictionary
# return response message with result or error message


def main():
	# validate the number of arguments and eventually print error message and exit with error
	# verify type of of arguments and eventually print error message and exit with error
	
 	#check if the user has entered the correct number of arguments
	if len(sys.argv) != 2:
		print("ERROR - Usage: python3 {} <port>".format(sys.argv[0]))
		sys.exit(1)
	
	port = sys.argv[1] #get the port from the arguments
	
	#check if the port is a number
	if not port.isdigit():
		print("ERROR - Port must be a number")
		sys.exit(1)
	else:
		port=int(port)
	
 	#check if the port is in the correct range
	if port<1024 or port>65535:
		print("ERROR - Port must be between 1024 and 65535")
		sys.exit(1)

	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create the server socket
	server_socket.bind(("127.0.0.1", port)) #bind the server socket to the port
	server_socket.listen(10) #listen for connections

	clients = [] #create a list of clients
	create_file() #create the report file
	print("SERVER - Waiting for connections at port {}".format(port)) #print that the server is waiting for connections
	
	while True:
		
		try:
			available = select.select([server_socket] + clients, [], [])[0] 
		except ValueError:
			# Sockets may have been closed, check for that
			for client in clients:
				if client.fileno() == -1: client.remove(client)  # closed
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
