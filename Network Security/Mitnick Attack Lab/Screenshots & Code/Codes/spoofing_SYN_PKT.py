from scapy.all import *

server_ip = "10.0.2.9"
server_port=1023

x_terminal_ip = "10.0.2.7"
x_terminal_port = 514
print("Sending SYN Packet")
ip = IP(src=server_ip, dst=x_terminal_ip)
tcp = TCP(sport=server_port, dport=x_terminal_port, flags="S", seq=1955201955)

send(ip/tcp, verbose=0)
