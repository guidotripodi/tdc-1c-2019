#! /usr/bin/env python
from scapy.all import *
import os
import socket
from datetime import datetime

# Seteo modo promiscuo
conf.sniff_promisc = True

if len(sys.argv) == 3:

    ftm="YYYYBBDDHHSS"
    d1 = datetime.now()
    paquetes = sniff( iface=sys.argv[1],store=1, timeout = 20000)
    d2 = datetime.now()

    diff = d2 - d1
    diff_minutos = diff.seconds/60
    nombreArchivo = 'sniff_{}_{}_{}.pcap'.format(sys.argv[2],datetime.now().strftime("%Y%m%d-%H%M%S"),diff_minutos)
    wrpcap(nombreArchivo,paquetes)



else:
    print("Introduzca el iface + nombre de la red")
