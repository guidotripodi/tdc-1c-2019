#!/usr/bin/python

import sys, os
from math import log as LOG
from scapy.all import *


def protocol_name(pkt):
    type_field = pkt[0].type
    if(type_field == 2048):
    	return "IP"
    if(type_field == 2054):
    	return "ARP"
    else:
    	#pongo otro porque no se que otros protocolos pueden ocurrir, hay que cargarlos a mano 
    	#o ver si existe una funcion de scapy que les ponga nombre (no encontre todavia)
    	return "otro"

def cast_type(pkt):
	dst_address = pkt[0].dst 
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
		nodes.append((a,i))

	nodes.sort(key=lambda n: n[1])
	print "Entropia", H, "Entropia maxima", LOG(len(nodes),2)
	for a,i in nodes[:20]:
		print a +"\t"+ ("%.5f" % (i-H)) + "\t" + ("*" if i-H < 0 else "")

def entropy_callback(pkt):

	try:
		#creo tupla <destino, protocolo>
		simbolo = (cast_type(pkt), protocol_name(pkt))
		simbolo = str(simbolo)
		#cuento apariciones de cada tipo de tupla
		if simbolo not in fuente: fuente[simbolo]=0
		fuente[simbolo] += 1

		
	except:
	 	return
	
	os.system("clear")

	

	
	MostrarNodosDistinguidos(fuente)
	#MostrarNodosDistinguidos(wh_dst)
	#MostrarNodosDistinguidos(wh_src)
	#MostrarNodosDistinguidos(ia_dst)
	#MostrarNodosDistinguidos(ia_src)


fuente = {} 
#wh_src = {}
#wh_dst = {}
#ia_src = {}
#ia_dst = {}

#no filtro por arp
sniff(prn=entropy_callback)


