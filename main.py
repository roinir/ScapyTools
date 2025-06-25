from scapy.all import *
import sys

ROUTER_MAC = "08:00:27:e9:7f:bd"
DST_MAC = "08:00:27:d0:a2:e2"

def sniff_leg(src_leg: str) -> Packet:
    print("Sniffing one packet")
    #store will save the packet and not dispose it
    #iface specifies the leg
    #count specifies the number of packets sniff accepts
    leg_sniff = sniff(store=True, iface=src_leg, count=1)
    return leg_sniff[0]

def send_message(dst_leg: str, packet: Packet) -> None:
    print(type(packet))
    packet.src = ROUTER_MAC
    packet.dst = DST_MAC
    #packet.show()
    prevTTL = (packet/IP()).ttl - 1
    sendp(packet/IP(ttl=prevTTL), iface=dst_leg)
def sniffer(src_leg: str, dst_leg: str) -> None:
    while True:
        packet = sniff_leg(src_leg)
        send_message(dst_leg, packet)

def main() -> None:
    if len(sys.argv) != 3:
        print("Sorry, those arguments are not allowed")
        return
    #send_message("enp0s3", sniff_leg("enp0s8"))
    sniffer(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()
