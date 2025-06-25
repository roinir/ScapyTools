from scapy.all import *
import sys

def sniff_leg(src_leg: str) -> Packet:
    print("Sniffing one packet")
    leg_sniff = sniff(session=TCPSession, prn=lambda x: x.summary(), store=True, iface=src_leg, count=1)
    return leg_sniff[0]

def send_message(dst_leg: str, packet: Packet) -> None:
    send(packet, iface=dst_leg)

def sniffer(src_leg: str, dst_leg: str) -> None:
    while True:
        send_message(dst_leg, sniff_leg(src_leg))

def main() -> None:
    if len(sys.argv) != 3:
        print("Sorry, those arguments are not allowed")
        return
    #send_message("enp0s3", sniff_leg("enp0s8"))
    sniffer(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()
