from scapy.all import IP, TCP, send
import time

target_ip = "2001:470:1f12:8::2"  # Replace with your target IP
target_port = 80  # Replace with the target port

for _ in range(200):  # Adjust the number of packets
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    send(packet, verbose=0)  # Sends the packet without verbose output
    time.sleep(0.05)  # Delay to control the rate (10 packets in 10 seconds)
