import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import argparse
import socket
import datetime


query_list = []
answer_dict = {}

def list_union(list1, list2):
	return list(set(list1).union(list2))

def list_intersection(list1, list2):
	return list(set(list1).intersection(list2))

def parser():
	parser = argparse.ArgumentParser(add_help = False)
	parser.add_argument("-i", nargs = '?')
	parser.add_argument("-r", nargs = '?')
	parser.add_argument("exp", nargs = '*')
	arg = parser.parse_args()

	return arg.i, arg.r, arg.exp

def is_ip(addr):
	try:
		if(type(addr) is not str):
			return False
		socket.inet_aton(addr)
		return True
	except socket.error:
		return False

def detect(pkt):
	
	ip_list =[]
	#print(pkt.time)
	if pkt.haslayer(DNSRR) and pkt[DNS].qr == 1 and pkt[DNS].ancount != 0:
		if pkt[DNS].id not in answer_dict.keys():
			for i in range(pkt[DNS].ancount):
				if is_ip(pkt[DNS].an[i].rdata):
					ip_list.append(pkt[DNS].an[i].rdata)
			answer_dict[pkt[DNS].id] = [ip_list, pkt.src, pkt[IP].ttl]
			all_ips = []

		elif pkt[DNS].id in answer_dict.keys():
			all_ips = answer_dict[pkt[DNS].id][0]
			for i in range(pkt[DNS].ancount):
				if is_ip(pkt[DNS].an[i].rdata):
					ip_list.append(pkt[DNS].an[i].rdata)
			if len(list_intersection(all_ips, ip_list)) != 0:
				answer_dict[pkt[DNS].id][0] = list_union(ip_list, all_ips)
			elif len(list_intersection(all_ips, ip_list)) == 0:
				if (answer_dict[pkt[DNS].id][1] != pkt.src) or (answer_dict[pkt[DNS].id][2] != pkt[IP].ttl): 
					
					print (datetime.datetime.fromtimestamp(pkt.time).strftime('%Y%m%d-%H:%M:%S.%f'), "DNS poisoning attempt")
					#print answer_dict
					#timestamp = datetime.datetime.fromtimestamp(pkt.time).strftime('%Y%m%d-%H:%M:%S.%f'))
					print ('TXID', hex(pkt[DNS].id), 'Request', pkt[DNS].qd.qname.decode('ASCII')) 
					print ('Answer1:', answer_dict[pkt[DNS].id][0])
					print ('Answer2:', ip_list)
				else:
					print ("No attack")
			#print(answer_dict)
		
		#print(answer_dict)	

if __name__ == '__main__':
	#hostdict = file_read()
	interface, tracefile, expression = parser()
	#print(interface)
	if interface:
		flagi = 1
	else:
		flagi = 0
	if tracefile:
		flagr = 1
	else:
		flagr = 0
	exp = '';
	for str in expression:
		exp = exp+' '+str
	if (flagi == 1) and (flagr ==0):
		sniff(filter = exp, iface = interface, prn = detect, store = 0)
		
	#elif (flagi == 0) and (flagr == 0):	
	#	sniff(filter = exp, prn = detect, store = 0)
	elif (flagr == 1) and (flagi == 0):
		sniff(offline = tracefile, prn = detect, store = 0, filter = exp)

	else:
		sniff(filter = exp, prn = detect, store = 0)


