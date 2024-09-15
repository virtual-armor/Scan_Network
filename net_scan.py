#!/usr/bin/env python

import scapy.all as sc

#discover clients on the same network
def scan(ip):
	#ARP - Address Resolution Protocol 
	#Address Resolution Protocol is a protocol that connects
	#a computer's IP address to its MAC address.

	#MAC - media access control

	#Ask who has a specific IP and return result to host machine IP
	#This function creates two packets and then combines them.
	#The packet has an ARP part and an Ether part
	arp_request = sc.ARP(pdst=ip)
	#arp_request.show()
	#print(arp_request.summary())
	#Use MAC address of ff:ff:ff:ff:ff:ff because devices communicate
	#by using their MAC addresses. Ths packet will be delivered
	#to each device in that network. This is a virtual MAC and does
	#not address to any specific device so that the packet will be
	#delivered to each device on the network.
	broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
	#broadcast.show()
	#sc.ls(sc.Ether)
	#Combine the two packets
	arp_ether_packet = broadcast/arp_request
	#print(arp_ether_packet.summary())
	#arp_ether_packet.show()
	#scapy.srp --> .srp: send and receive packets at Layer 2 whereas
	#.sr sends and receives packets at layer 3
	#Set srp verbosity to false to not include extraneous information.
	ans = sc.srp(arp_ether_packet, timeout=1.1, verbose=False)[0]
	#Print header
	print("IP\t\t\tMAC Address\n-------------------------------------------")
	#print IP and MAC of connected device that replied
	for a in ans:
		print(a[1].psrc + "\t\t" + a[1].hwsrc)
	#ans.show()	
	
scan("172.16.251.0/24")
