import sys
from scapy.all import *

MAX_TTL = 30

IP_input = raw_input("Please enter an IP address for traceroute: ")
print "You entered: ", IP_input

finished = False
for ttl in range(1,MAX_TTL):
	if finished:
		print "Traceroute finished. Route to IP address traced successfully."
		break
	pkt = IP(dst=IP_input, ttl=ttl) / TCP(flags=0x02) #TCP SYN packets
	ans = sr1(pkt, verbose=0)
	if ans.src == IP_input:
		finished = True
	print ttl,": ",ans.src
