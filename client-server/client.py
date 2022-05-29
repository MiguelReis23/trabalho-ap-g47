#!/usr/bin/python3

import numbers
import os
import sys
import socket
import json
import base64
from urllib import response

from common_comm import send_dict, recv_dict, sendrecv_dict

from Crypto.Cipher import AES

# Função para encriptar valores a enviar em formato json com codificação base64
# return int data encrypted in a 16 bytes binary string coded in base64
def encrypt_intvalue (cipherkey, data):
	if cipherkey is None:
		return data
	cipher = AES.new(cipherkey, AES.MODE_ECB)
	dataencrypted= cipher.encrypt(bytes("%16d"%(data), "utf-8"))
	dataenctyptedtosend= base64.b64encode(dataencrypted)
	return str(dataenctyptedtosend, "utf-8")
	


# Função para desencriptar valores recebidos em formato json com codificação base64
# return int data decrypted from a 16 bytes binary strings coded in base64
def decrypt_intvalue (cipherkey, data):
	if cipherkey is None:
		return data
	cipher= AES.new(cipherkey, AES.MODE_ECB)
	datadecoded= base64.b64encode(data)
	datadecrypted= cipher.decrypt(bytes(datadecoded))
	return int(str(datadecrypted, "utf-8"))


# verify if response from server is valid or is an error message and act accordingly
def validate_response (client_sock, response):
	if "error" in response:
		print ("ERROR - %s" % (response["error"]))
		client_sock.close ()
		sys.exit (3)
	return True


# process QUIT operation
def quit_action (client_sock):
	response = sendrecv_dict (client_sock, {"op": "QUIT"})
	if "error" in response:
		print ("ERROR -  %s" % (response["error"]))
		client_sock.close ()
		sys.exit (4)
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
	cipherkey=None
	cipherkeytosend=None
	op= ""
	numbers=[]	
	
	encrypt= input("CLIENT - Do you want to encrypt the numbers? (y/n): ")
	while encrypt.upper() != "Y" and encrypt != "N":
		print ("ERROR -  Invalid option")
		encrypt= input("CLIENT - Do you want to encrypt the numbers? (y/n): ")
	if encrypt.upper() == "Y" :
		cipherkey= os.urandom(16)
		cipherkeytosend= str(base64.b64encode(cipherkey), "utf8")
	
     
	response= sendrecv_dict (client_sock, {"op": "START", "client_id": client_id, "cipher": cipherkeytosend})
	validate_response (client_sock, response)
	print ("Operation START successfully executed" )
 
	while op.upper() != "QUIT" or op!= "STOP":
		op= input("Enter operation(QUIT, STOP) or number: ")
		
		if op.upper() == "STOP":
			response= sendrecv_dict (client_sock, {"op": "STOP"})
			validate_response (client_sock, response)
			print ("Operation STOP successfully executed" )
			print ("CLIENT - Numbers: {}, Min: {}, Max: {}".format(numbers, min(numbers), max(numbers)))
			break
		elif op.upper() == "QUIT":
			quit_action (client_sock)
			print ("Operation QUIT successfully executed" )
			break
		else:
			try:
				number=int(op)
				numbers.append(number)
			except ValueError:
				print ("ERROR - Invalid number or operation")
				continue
				
			response= sendrecv_dict (client_sock, {"op": "NUMBER", "number": encrypt_intvalue(cipherkey, int(number))})
			validate_response (client_sock, response)
			print ("CLIENT - Number {} sent".format(number))



 
 
def main():
	# validate the number of arguments and eventually print error message and exit with error
	# verify type of of arguments and eventually print error message and exit with error
	if len(sys.argv) <3 or len(sys.argv) > 4:
		print ("ERROR - Usage: python3 {} <client_id> <port> <host>".format(sys.argv[0]))
		sys.exit (1)
	if not sys.argv[2].isdigit():
		print ("ERROR - Invalid port")
		sys.exit (2)
	
	client_id = sys.argv[1]
	port = int(sys.argv[2])
	hostname = sys.argv[3] if len(sys.argv) > 3 else "localhost"

	# create a socket and connect to the server
	client_sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	client_sock.connect ((hostname, port))

	run_client (client_sock, client_id)

	client_sock.close ()
	sys.exit (0)

if __name__ == "__main__":
	main()












