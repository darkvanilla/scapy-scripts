import sys
from scapy.all import *

#####
# TCP Port Scanning
# Scans for the TCP ports on the target IP address.
#
# Returns all the OPEN, CLOSED and FILTERED ports of the target.
#
# Author: Birkan Mert Erenler
#
# How To Run?
#   -> Open a command line, type 'python port-scan-tcp.py TARGET_IP_ADDRESS'
#   -> Example: python port-scan-tcp.py 192.168.1.1
#####

# Get the target IP address from the standard input:
IP_ADDR = input("Please enter a target IP address for TCP port scanning: ")
print("You have entered: ", IP_ADDR)

PORT_RANGE = range(0,65536)

# Port Status Constants:
OPEN = 0
CLOSED = 1
FILTERED = 2

# Inspect the status of a given port:
def inspect_status(pkt, ans, port, start):
	if ans == None and start:
		ans = sr1(pkt, timeout=1, verbose=0)
		inspect_status(pkt, ans, port, not start)
	elif ans == None and not start:
		return FILTERED
	else:
		if ans[TCP].flags == 0x12: #flags = 'SA'
			return OPEN
		elif ans[TCP].flags == 0x14: #flags = 'RA'
			return CLOSED
		elif isinstance(ans.payload, ICMP):
			return FILTERED
	return FILTERED

port_status_array = [None]*(len(PORT_RANGE))

print 'Scanning all TCP ports for target IP address you have entered...   '
for port in PORT_RANGE:
	pkt = IP(dst=IP_ADDR) / TCP(dport=port,flags='S') #a TCP SYN packet
	ans = sr1(pkt, timeout=1, verbose=0)
	port_status_array[port] = inspect_status(pkt, ans, port, True)

# Output the results:
port_status = tuple(enumerate(port_status_array))
port_status = sorted(port_status, key=lambda x: x[1])

port = 0
print('OPEN: '),
while port in PORT_RANGE and port_status[port][1] == OPEN:
	print(str(port_status[port][0]) + ', '),
	port += 1
print('\nCLOSED: '),
while port in PORT_RANGE and port_status[port][1] == CLOSED:
	print(str(port_status[port][0]) + ', '),
	port += 1
print('\nFILTERED: '),
while port in PORT_RANGE and port_status[port][1] == FILTERED:
	print(str(port_status[port][0]) + ', '),
	port += 1
