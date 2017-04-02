import sys
from scapy.all import *

RTR_IP_ADDR = '10.10.111.1'

self_MAC_addr = '02:1D:07:00:02:39'
local_MAC = get_if_hwaddr('eth0')
local_MAC_raw = self_MAC_addr.replace(':','').decode('hex')

#PORT 53 - DNS
pkt = IP(dst=RTR_IP_ADDR) / UDP(dport=53) 
pkt /= DNS(rd=1,qd=DNSQR(qname='www.google.com'))
ans = sr1(pkt, timeout=120, verbose=0)

print('Port 53: '),
if ans == None:
	print 'OPEN|FILTERED (no response from DNS server...)'
else:
	print 'OPEN (running DNS server...)'
	print 'Answer Summary: ' + str(ans.summary())

#PORT 67 - BOOTP/DHCP SERVER
pkt2 = Ether(src=local_MAC, dst='FF:FF:FF:FF:FF:FF')
pkt2 /= IP(src='10.10.111.107',dst=RTR_IP_ADDR) / UDP(sport=68,dport=67)
pkt2 /= BOOTP(chaddr=local_MAC_raw, xid=RandInt(), op=1) #op1 -> BootP Request
pkt2 /= DHCP(options=[('message-type','request'),('requested_addr','10.10.111.107'),'end'])
ans = srp1(pkt2, timeout=20, iface='eth0', verbose=0)

print('Port 67: '),
if ans == None:
	print 'OPEN|FILTERED (no response from DHCP server...)'
else:
	print 'OPEN (running DHCP server...)'
	print 'Answer Summary: ' + str(ans.summary())

#PORT 68 - BOOTP/DHCP CLIENT
pkt3 = Ether(src=local_MAC, dst='FF:FF:FF:FF:FF:FF')
pkt3 /= IP(src='10.10.111.107',dst=RTR_IP_ADDR) / UDP(sport=67,dport=68)
pkt3 /= BOOTP(chaddr=local_MAC_raw, yiaddr=RTR_IP_ADDR,siaddr='10.10.111.107',xid=RandInt(),op=1)
pkt3 /= DHCP(options=[('message-type','offer'),('subnet_mask','255.255.255.0'),('server_id', '10.10.111.107'), ('lease_time', 3600), 'end'])
ans = srp1(pkt3, timeout=20, iface='eth0', verbose=0)

print('Port 68: '),
if ans == None:
	print 'OPEN|FILTERED (no response from DHCP client...)'
else:
	print 'OPEN (running DHCP client...)'
	print 'Answer Summary: ' + str(ans.summary())
