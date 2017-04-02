import sys
from scapy.all import *
import time

#####
# TCP Port Scanning
# Scans for the UDP ports (only first 1024 ports) on the target IP address.
#
# Returns the OPEN|FILTERED and CLOSED UDP ports of the target.
#
# Since some systems (e.g. Linux) limits the number of ICMP response packets
# in a given timespan, the script limits the port scanning with 1 port / sec.
# Thus, it will approximately take 17 mins to complete the scan.
#
# Author: Birkan Mert Erenler
#
# How To Run?
#   -> Open a command line, type 'python port-scan-udp.py TARGET_IP_ADDRESS'
#   -> Example: python port-scan-udp.py 192.168.1.1
#####

# Get the target IP address from the standard input:
IP_ADDR = input("Please enter a target IP address for UDP port scanning: ")
print("You have entered: ", IP_ADDR)

PORT_RANGE = range(0,1024)

#Port Status Constants:
OPEN_FILTERED = 0
CLOSED = 1

# Inspect the status of a given port:
def inspect_status(pkt, ans, port, start):
	if ans == None and start:
		ans = sr1(pkt, timeout=1, verbose=0)
		inspect_status(pkt, ans, port, not start)
	elif ans == None and not start:
		return OPEN_FILTERED
	else:
		if isinstance(ans.payload, ICMP):
			time.sleep(1)
			return CLOSED
		else:
			return OPEN_FILTERED
	return OPEN_FILTERED

port_status_array = [None]*(len(PORT_RANGE))

# Scan:
print 'Scanning UDP ports 0-1023 of target IP address you have entered ...   '
for port in PORT_RANGE:
	pkt = IP(dst=IP_ADDR) / UDP(dport=port)
	ans = sr1(pkt, timeout=1, verbose=0)
	port_status_array[port] = inspect_status(pkt, ans, port, True)

# Output the results:
port_status_enum = tuple(enumerate(port_status_array))
port_status = sorted(port_status_enum, key=lambda x: x[1])

port = 0
print('OPEN|FILTERED: '),
while port in PORT_RANGE and port_status[port][1] == OPEN_FILTERED:
	print(str(port_status[port][0]) + ', '),
	port += 1
print('\nCLOSED: '),
while port in PORT_RANGE and port_status[port][1] == CLOSED:
	print(str(port_status[port][0]) + ', '),
	port += 1
