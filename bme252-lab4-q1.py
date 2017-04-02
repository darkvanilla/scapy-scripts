import sys
from scapy.all import *

RTR_IP_ADDR = '10.10.111.1'
PORT_RANGE = range(0,100+1) #interval [0,100]

#Port Status Constants:
OPEN = 0
CLOSED = 1
FILTERED = 2

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

print 'Scanning TCP ports 0-100 for target rtr @10.10.111.1...   '
for port in PORT_RANGE:
	pkt = IP(dst=RTR_IP_ADDR) / TCP(dport=port,flags='S') #a TCP SYN packet
	ans = sr1(pkt, timeout=1, verbose=0)
	port_status_array[port] = inspect_status(pkt, ans, port, True)

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
