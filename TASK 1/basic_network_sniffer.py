from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw


def packet_callback(packet):
    print("\n" + "=" * 60)
    print("PACKET CAPTURED")
    print("=" * 60)

    # ARP packet
    if packet.haslayer(ARP):
        arp = packet[ARP]

        print("Protocol: ARP")
        print(f"Source MAC:      {arp.hwsrc}")
        print(f"Source IP:       {arp.psrc}")
        print(f"Destination MAC: {arp.hwdst}")
        print(f"Destination IP:  {arp.pdst}")

        return

    # IP packet
    if packet.haslayer(IP):

        ip = packet[IP]

        print(f"Source IP:       {ip.src}")
        print(f"Destination IP:  {ip.dst}")
        print(f"IP Protocol:     {ip.proto}")
        print(f"Packet Length:   {len(packet)} bytes")

        # TCP
        if packet.haslayer(TCP):

            tcp = packet[TCP]

            print("Transport:       TCP")
            print(f"Source Port:     {tcp.sport}")
            print(f"Destination Port:{tcp.dport}")
            print(f"TCP Flags:       {tcp.flags}")

        # UDP
        elif packet.haslayer(UDP):

            udp = packet[UDP]

            print("Transport:       UDP")
            print(f"Source Port:     {udp.sport}")
            print(f"Destination Port:{udp.dport}")

        # ICMP
        elif packet.haslayer(ICMP):

            print("Transport:       ICMP")

        # Payload
        if packet.haslayer(Raw):

            payload = packet[Raw].load

            print(f"Payload Length:  {len(payload)} bytes")

            # Display first 80 bytes
            print("Payload:")

            try:
                print(payload[:80].decode("utf-8", errors="replace"))
            except Exception:
                print(payload[:80])

        else:
            print("Payload:         None")


print("==============================================")
print("       BASIC NETWORK PACKET SNIFFER")
print("==============================================")
print("Starting packet capture...")
print("Press CTRL+C to stop.\n")

packets = sniff(
    prn=packet_callback,
    store=True
)

packets.save("captured_packets.pcap")