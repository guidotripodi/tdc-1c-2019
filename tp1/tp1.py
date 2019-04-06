#!/usr/bin/python

import sys, os
from math import log as LOG
from scapy.all import *

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
		if pkt[ARP].op == 1: #who-has (request)
			if pkt[ARP].psrc not in wh_src: wh_src[pkt[ARP].psrc]=0
			wh_src[pkt[ARP].psrc]+=1
			if pkt[ARP].pdst not in wh_dst: wh_dst[pkt[ARP].pdst]=0
			wh_dst[pkt[ARP].pdst]+=1

		if pkt[ARP].op == 2: #is-at (response)
			if pkt[ARP].psrc not in ia_src: ia_src[pkt[ARP].psrc]=0
			ia_src[pkt[ARP].psrc]+=1
			if pkt[ARP].pdst not in ia_dst: ia_dst[pkt[ARP].pdst]=0
			ia_dst[pkt[ARP].pdst]+=1
	except:
		return

	os.system("clear")
	MostrarNodosDistinguidos(wh_dst)
	MostrarNodosDistinguidos(wh_src)
	#MostrarNodosDistinguidos(ia_dst)
	#MostrarNodosDistinguidos(ia_src)

wh_src = {}
wh_dst = {}
ia_src = {}
ia_dst = {}

sniff(prn=entropy_callback, filter="arp")


