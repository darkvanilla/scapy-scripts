import sys
from scapy.all import *

IP_input = raw_input("Please enter an IP address for ICMP to be sent: ")
print "You entered: ", IP_input

l3 = IP(dst=IP_input) / ICMP() #send default ICMP packet
l3.show()
ans,unans = sr(l3)
print ans,unans
ans.summary()
