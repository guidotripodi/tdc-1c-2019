#! /usr/bin/env python2.7
import argparse
from tp1 import *
from plotter import Plotter
from scapy.all import rdpcap

if __name__ == "__main__":
    #Parse command line arguments
	parser = argparse.ArgumentParser(description='Script for plotting network packet related data.')
	parser.add_argument("file", help="Pcap formatted capture")
	args = parser.parse_args()

	pcap = rdpcap(args.file)

	S2 = Source2(pcap)
	plotter = Plotter(S2)
	
	saveFigure(plotter.probabilityPlot(),args.file, 2)
	saveFigure(plotter.informationPlot(),args.file, 2)
