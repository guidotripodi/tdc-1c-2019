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
    # el parametro count es el maximo de paquetes que queremos capturar. Para los ejs nos piden > 10.000
    paquetes = sniff(count = 15000, iface=sys.argv[1],store=1)
    d2 = datetime.now()

    diff = d2 - d1
    diff_minutos = diff.seconds/60
    nombreArchivo = 'sniff_{}_{}_{}.pcap'.format(sys.argv[2],datetime.now().strftime("%Y%m%d-%H%M%S"),diff_minutos)
    wrpcap(nombreArchivo,paquetes)



else:
    print("Introduzca el iface + nombre de la red")
