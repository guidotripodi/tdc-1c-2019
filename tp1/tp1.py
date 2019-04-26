#!/usr/bin/python


from math import log as LOG
import argparse 
from scapy.all import rdpcap                                              
from scapy.all import *
from sets import Set
from collections import Counter
import math
import csv
import os
from collections import Counter
from math import log
#import plotly.plotly as py
tramas = 0


class CsvPrinter():
    def __init__(self, source, nPackets):
        self.source = source
        self.packetCount = nPackets
        self.sourceRows = list(map(lambda (protocol, count):
            (protocol, P(count, self.source.N), I(P(count, self.packetCount))),
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
			wr.writerow(('Entropia Maxima', self.source.maxEntropy))

class Source1():

    def __init__(self, pcap):
    	#inicializo string y contador de messages
        S1 = []
        self.nUnicastMessages = 0
        self.nBrodcastMessages = 0

        for pkt in pcap:
        	#armo mi tupla (broadcast/unicast, protocol), aca podria setear los protocolos ARP IPV4 IPV6 y algun otro
            protocol = pkt.payload.name
            if pkt.dst == "ff:ff:ff:ff:ff:ff":
                fstTupla = "broadcast"
                self.nBrodcastMessages += 1
            else:
                fstTupla = "unicast"
                self.nUnicastMessages += 1

            S1.append(str((fstTupla, protocol)).replace("'", ""))
        self.N = len(S1)
        self.sourceCount = Counter(S1)
        self.entropy = reduce((lambda x, v: x + Ei(v, len(pcap))), self.sourceCount.itervalues(), 0)
        self.maxEntropy = math.log(len(self.sourceCount.keys()), 2) 
    
    def name(self):
        return "Fuente 1"

class Source2():

	def __init__(self, pcap):
		self.metadata = []
		S2 = []
                arpPackets = pcap[ARP]
		for packet in arpPackets:
			#self.metadata.append((packet.psrc, packet.pdst))
			S2.append(packet.pdst)
			S2.append(packet.psrc)

		self.N = len(S2)
		self.sourceCount = collections.Counter(S2)
		self.entropy = reduce((lambda x, v: x + Ei(v, len(arpPackets))), self.sourceCount.itervalues(), 0)
		self.maxEntropy = 0 if len(self.sourceCount.keys()) == 0 else math.log(len(self.sourceCount.keys()), 2) 

	def name(self):
		return "Fuente 2"


def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name
'''
estas funciones podrian ser llamadas desde otro archivo, para que no quede todo desordenado
'''
def P(x, total):
	return x/float(total)

'''
Given a probability of a symbol returns the information of the symbol 
'''
def I(p):
	return -math.log(p, 2)

'''
Symbol entropy
'''
def Ei(x, total):
	pi = P(x, total)
	return pi*I(pi)

def saveFigure(figure, input_file_name, sourceNumber):
	directory = 'graficos/'

	source = "Source" + str(sourceNumber)

	if not os.path.exists(directory):
		os.makedirs(os.path.dirname(directory))	
    
	folders = input_file_name.split('/')
	input_file_name = folders[len(folders) - 1]
	name = directory + figure.name() + "_" + input_file_name.replace('.pcap', "_" + source + '.png') 
	py.image.save_as(figure.figure, filename=name)



if __name__ == "__main__":
	#Parse command line arguments
	parser = argparse.ArgumentParser(description='Script for analizing network packets.')
	parser.add_argument("file", help="Pcap formatted capture")            
	args = parser.parse_args()    
	pcap = rdpcap(args.file)

	#levanto pcap para s1
	S1 = Source1(pcap)
	#imprimo en csv, ver si lo terminamos sacando asi o por pantalla.
	csv1 = CsvPrinter(S1, len(pcap))
	csv1.createCSV(args.file)
                                     
            
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
