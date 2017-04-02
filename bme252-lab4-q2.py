import sys
from scapy.all import *
import time

RTR_IP_ADDR = '10.10.111.1'
PORT_RANGE = range(0,100+1) #interval [0,100]

#Port Status Constants:
OPEN_FILTERED = 0
CLOSED = 1

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

print 'Scanning UDP ports 0-100 for target rtr @10.10.111.1...   '
for port in PORT_RANGE:
	pkt = IP(dst=RTR_IP_ADDR) / UDP(dport=port)
	ans = sr1(pkt, timeout=1, verbose=0)
	port_status_array[port] = inspect_status(pkt, ans, port, True)

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
