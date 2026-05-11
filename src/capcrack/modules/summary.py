from collections import Counter

from capcrack.tshark import run_tshark


def run_summary(pcap):
    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "_ws.col.Protocol"
    ]

    rows = run_tshark(pcap, fields)

    protocols = Counter()
    ips = Counter()
    ports = Counter()

    for row in rows:
        proto = row.get("_ws.col.Protocol")
        if proto:
            protocols[proto] += 1

        for key in ["ip.src", "ip.dst"]:
            value = row.get(key)
            if value:
                ips[value] += 1

        for key in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
            value = row.get(key)
            if value:
                ports[value] += 1

    print("=== PCAP Summary ===")
    print(f"Packets: {len(rows)}")

    print("\tTop protocols:")
    for proto, count in protocols.most_common(10):
        print(f"  {proto:12} {count}")

    print("\tTop IPs:")
    for ip, count in ips.most_common(10):
        print(f"  {ip:20} {count}")

    print("\tTop ports:")
    for port, count in ports.most_common(10):
        print(f"  {port:8} {count}")