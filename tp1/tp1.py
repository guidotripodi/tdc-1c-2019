#!/usr/bin/python

import sys, os
from math import log as LOG
from scapy.all import *

tramas = 0

def protocol_name(pkt):
    type_field = pkt[Ether].type
    if(type_field == 2048):
    	return "IPv4"
    if(type_field == 2054):
    	return "ARP"
    if(type_field == 34525):
    	return "IPv6"
    else:
    	#pongo otro porque no se que otros protocolos pueden ocurrir, hay que cargarlos a mano 
    	#o ver si existe una funcion de scapy que les ponga nombre (no encontre todavia)
    	return str(pkt[Ether].type)

def cast_type(pkt):
	dst_address = pkt[Ether].dst 
	#hay que chequear si esto esta bien
	if(dst_address == "ff:ff:ff:ff:ff:ff"):
		return "broadcast"
	else:
		return "unicast"



def MostrarNodosDistinguidos(source):
	H = 0
	N = sum(source.values())

	nodes = []
	for a, c in source.iteritems():
		p = c/float(N)
		i = -LOG(p, 2)
		H += p * i
		nodes.append((a,p,i))

	nodes.sort(key=lambda n: n[1])
	print "Entropia", H, "Entropia maxima", LOG(len(nodes),2), "#tramas", tramas
	for a,p,i in nodes[:20]:
		#agrego para que muestre probabilidad e informacion del simbolo
		print a +"\t"+ str("%.5f" % p) +"\t" + str("%.5f" % i) +"\t" + ("%.5f" % (i-H)) + "\t" + ("*" if i-H < 0 else "")

def entropy_callback(pkt):
	global tramas
	tramas += 1
	try:
		#creo tupla <destino, protocolo>
		simbolo = (cast_type(pkt), protocol_name(pkt))
		simbolo = str(simbolo)
		#cuento apariciones de cada tipo de tupla (cada simbolo)
		if simbolo not in fuente: fuente[simbolo]=0
		fuente[simbolo] += 1

		
	except:
	 	return
	
	os.system("clear")

	

	
	MostrarNodosDistinguidos(fuente)
	

fuente = {} 


#no filtro por arp
sniff(prn=entropy_callback)


