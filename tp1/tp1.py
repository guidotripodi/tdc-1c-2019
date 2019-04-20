#!/usr/bin/python

import sys, os
from math import log as LOG
from scapy.all import *
import math
import csv
import os
tramas = 0


class CsvPrinter():
    def __init__(self, source, nPackets):
        self.source = source
        self.packetCount = nPackets
        self.sourceRows = list(map(lambda (protocol, count):
            (protocol, P(count, self.packetCount), I(P(count, self.packetCount))),
            self.source.sourceCount.iteritems()))
         
    def createCSV(self, pcapFilename):
		directory = "tables/"

		if not os.path.exists(directory):
			os.makedirs(os.path.dirname(directory))	

		folders = pcapFilename.split('/')
		input_file_name = folders[len(folders) - 1]
		fileName = directory + input_file_name.split('.')[0] + "_" + self.source.name().replace(" ", "") + ".csv"
		with open(fileName, 'wb') as myfile:
			wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
			wr.writerow(('Simbolo', 'Probabilidad', 'Informacion'))
			for item in self.sourceRows:
				wr.writerow(item)
			wr.writerow(('Entropia de la fuente', self.source.entropy))
			wr.writerow(('Entropia Máxima', self.source.maxEntropy))

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

class Source2():

	def __init__(self, pcap):
		self.metadata = []
		S2 = []
                arpPackets = pcap[ARP]
		for packet in arpPackets:
			self.metadata.append((packet.psrc, packet.pdst))
			S2.append(packet.pdst)
			S2.append(packet.psrc)

		self.sourceCount = Counter(S2)
		self.entropy = reduce((lambda x, v: x + Ei(v, len(arpPackets))), self.sourceCount.itervalues(), 0)
		self.maxEntropy = log(len(self.sourceCount.keys()), 2) 

	def name(self):
		return "Fuente 2"



#no filtro por arp
sniff(prn=entropy_callback)


if __name__ == "__main__":

	S2 = Source2(pcap)
	csv2 = CsvPrinter(S2, len(pcap))
	csv2.createCSV(args.file)

'''
Source2 tiene que aportar la suficiente informacion como para poder distingir hosts a traves de los paquetes ARP: 
Los paquetes ARP pueden ser de operacion who-has o is-at, siendo la segunda la respuesta de la primera. Se tomara como supuesto
que el nodo cuya IP va a ser mas solicitada por who-has va a tener que ser la del default-gateway, ya que las redes analizadas mayormente
se usan para el acceso a internet (minimizamos totalmente los mensajes ARP entre hosts de la misma red)

Distinguir simbolos:
La metadata se guarda en forma de tupla (ipsrc , ipdst) del mensaje who-has, pero cada simbolo es solamente ipdst ya que estamos tratando de distinguir al router
para asi distinguir a los hosts
'''
