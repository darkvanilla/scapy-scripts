import sys
from scapy.all import *

#####
# TCP TraceRoute
# Traces the network route from this machine to the destination IP.
#
# Author: Birkan Mert Erenler
#
# How To Run?
#   -> Open a command line, type 'python traceroute-tcp.py TARGET_IP_ADDRESS'
#   -> Example: python traceroute-tcp.py 127.0.0.1
#####

MAX_TTL = 30 # maximum no. of hops to end traceroute

IP_input = input("Please enter an IP address for traceroute: ")
print("You entered: ", IP_input)

finished = False
for ttl in range(1,MAX_TTL):
	pkt = IP(dst=IP_input, ttl=ttl) / TCP(flags=0x02) #TCP SYN packets
	ans = sr1(pkt, verbose=0)
	print(ttl,": ",ans.src)
	if ans.src == IP_input:
		print("Traceroute finished. Route to IP address traced successfully.")
		break
