#!/usr/bin/python3

import os
import sys
import socket
import json
import base64

from common_comm import send_dict, recv_dict, sendrecv_dict

from Crypto.Cipher import AES

# Função para encriptar valores a enviar em formato json com codificação base64
# return int data encrypted in a 16 bytes binary string coded in base64
def encrypt_intvalue (cipherkey, data):
	if cipherkey is None: #check if cipherkey exists
		return data
	cipher = AES.new(cipherkey, AES.MODE_ECB) #create cipher
	dataencrypted= cipher.encrypt(bytes("%16d"%(data), "utf8")) #encrypt data
	dataencryptedtosend= base64.b64encode(dataencrypted) #encode data
	return str(dataencryptedtosend, "utf8") #return data encrypted
	


# Função para desencriptar valores recebidos em formato json com codificação base64
# return int data decrypted from a 16 bytes binary strings coded in base64
def decrypt_intvalue (cipherkey, data):
	if cipherkey is None: #check if cipherkey exists
		return data
	cipher= AES.new(cipherkey, AES.MODE_ECB) #create cipher
	datadecoded= base64.b64decode(data) #decode data
	datadecrypted= cipher.decrypt(datadecoded) #decrypt data
	return int(str(datadecrypted, "utf8")) #return decrypted data


# verify if response from server is valid or is an error message and act accordingly
def validate_response (client_sock, response):
	if "error" in response: # check if response is an error message
		print ("ERROR - %s" % (response["error"])) # print error message
		client_sock.close () # close socket
		sys.exit (3) # exit with error
	return True


# process QUIT operation
def quit_action (client_sock):
	response = sendrecv_dict (client_sock, {"op": "QUIT"}) # send QUIT operation
	if "error" in response: # check if response is an error message
		print ("ERROR -  %s" % (response["error"])) # print error message
		client_sock.close () # close socket
		sys.exit (4) # exit with error
	return None


# Outcomming message structure:
# { op = "START", client_id, [cipher] }
# { op = "QUIT" }
# { op = "NUMBER", number }
# { op = "STOP" }
#
# Incomming message structure:
# { op = "START", status }
# { op = "QUIT" , status }
# { op = "NUMBER", status }
# { op = "STOP", status, min, max }


#
# Suporte da execução do cliente
#
def run_client (client_sock, client_id):
	cipherkey=None #cipherkey is None by default
	cipherkeytosend=None #cipherkeytosend is None by default
	op= "" #op is empty by default
	numbers=[] #numbers is empty by default
	
	encrypt= input("CLIENT - Do you want to encrypt the numbers? (y/n): ") #ask if user wants to encrypt numbers
	while encrypt.upper() != "Y" and encrypt.upper() != "N": #check if user input is valid
		print ("ERROR -  Invalid option") #print error message if user input is invalid
		encrypt= input("CLIENT - Do you want to encrypt the numbers? (y/n): ") #ask again if user wants to encrypt numbers
	if encrypt.upper() == "Y" :
		cipherkey= os.urandom(16) #create random cipherkey
		cipherkeytosend= str(base64.b64encode(cipherkey), "utf8") #encode cipherkey
	
     
	response= sendrecv_dict (client_sock, {"op": "START", "client_id": client_id, "cipher": cipherkeytosend}) #send START operation
	validate_response (client_sock, response) #verify if response is valid
	print ("Operation START successfully executed" ) #print message if operation is successful
 
	while op.upper() != "QUIT" or op!= "STOP": #check if user wants to quit or stop
		op= input("CLIENT - Enter operation(QUIT, STOP) or number: ") #ask user for operation
		
		if op.upper() == "STOP": #check if user wants to stop
			response= sendrecv_dict (client_sock, {"op": "STOP"}) #send STOP operation
			validate_response (client_sock, response) #verify if response is valid
			print ("Operation STOP successfully executed" ) #print message if operation is successful
			print ("CLIENT - Numbers: {}, Min: {}, Max: {}".format(numbers, min(numbers), max(numbers))) #print numbers and min and max
			break
		elif op.upper() == "QUIT": #check if user wants to quit
			quit_action (client_sock) #process QUIT operation
			print ("Operation QUIT successfully executed" ) #print message if operation is successful
			break 
		else:
			try:
				number=int(op) #try to convert user input to int
				numbers.append(number) #add number to list
			except ValueError: #check if user input is not a number
				print ("ERROR - Invalid number or operation") #print error message
				continue
				
			response= sendrecv_dict (client_sock, {"op": "NUMBER", "number": encrypt_intvalue(cipherkey,number)}) #send NUMBER operation
			validate_response (client_sock, response) #verify if response is valid
			print ("CLIENT - Number {} sent".format(number)) #print message if operation is successful



 
 
def main():
	# validate the number of arguments and eventually print error message and exit with error
	# verify type of of arguments and eventually print error message and exit with error
	if len(sys.argv) <3 or len(sys.argv) > 4: #check if number of arguments is valid
		print ("ERROR - Usage: python3 {} <client_id> <port> <host>".format(sys.argv[0])) #print error message and correct usage
		sys.exit (1) #exit with error
	if not sys.argv[2].isdigit(): #check if port is a number
		print ("ERROR - Invalid port") #print error message
		sys.exit (2) #exit with error
	
	client_id = sys.argv[1] #get client id from arguments
	port = int(sys.argv[2]) #get port from arguments
	hostname = sys.argv[3] if len(sys.argv) > 3 else "localhost" #get hostname from arguments if exists, otherwise use localhost

	# create a socket and connect to the server
	client_sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM) #create socket
	client_sock.connect ((hostname, port)) #connect to server

	run_client (client_sock, client_id) #process client

	client_sock.close () #close socket
	sys.exit (0) #exit with success

if __name__ == "__main__":
	main()












