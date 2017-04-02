import sys
from scapy.all import *

net_input = raw_input("Please enter a network IP address range (CIDR): ")
print "You entered: ", net_input

if net_input.find('/') != -1: #if a subnet is entered by the user
	all_IPs = Net(net_input)
	list_all_IPs = [ip for ip in all_IPs]
   #Exclude Network and Broadcast Addresses:
	all_IPs_legitimate = list_all_IPs[1:len(list_all_IPs)-1]
else: #if only 1 IP address is entered by the user
	all_IPs_legitimate = net_input

l3 = IP(dst=all_IPs_legitimate) / TCP(dport=[80,53])
l3.show()
