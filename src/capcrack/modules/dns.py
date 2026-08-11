import re
from collections import Counter, defaultdict

from capcrack.tshark import run_tshark


COMMON_QTYPES = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "29": "LOC",
    "33": "SRV",
    "255": "ANY",
}


HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
BASE64ISH_RE = re.compile(r"^[A-Za-z0-9_-]{20,}={0,2}$")


def qtype_name(value):
    if not value:
        return ""
    return COMMON_QTYPES.get(value, value)


def base_domain(domain):
    """
    Base domain guess.

    Unable to perfectly handle things like .co.uk 
    """
    labels = domain.strip(".").split(".")
    if len(labels) < 2:
        return domain

    return ".".join(labels[-2:])


def is_base64ish_label(label):
    # Detect labels that look like encoded chunks
    if len(label) < 20:
        return False

    if not BASE64ISH_RE.fullmatch(label):
        return False

    has_letter = any(c.isalpha() for c in label)
    has_digit = any(c.isdigit() for c in label)

    return has_letter and has_digit


def is_hex_label(label):
    if len(label) < 16:
        return False

    return bool(HEX_RE.fullmatch(label))


def analyze_query_name(qname):
    reasons = []

    clean = qname.strip(".")
    labels = clean.split(".")

    longest_label = max((len(label) for label in labels), default=0)

    if len(clean) > 80:
        reasons.append("very long domain name")

    if longest_label > 40:
        reasons.append("very long DNS label")

    for label in labels:
        if is_hex_label(label):
            reasons.append("hex-looking label")
            break

    for label in labels:
        if is_base64ish_label(label):
            reasons.append("base64-like label")
            break

    return reasons


def run_dns(pcap):
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "dns.qry.name",
        "dns.qry.type",
        "dns.flags.rcode",
        "dns.flags.response",
        "dns.a",
        "dns.aaaa",
        "dns.cname",
        "dns.txt",
    ]

    rows = run_tshark(pcap, fields, "dns")

    if not rows:
        print("=== DNS Analysis ===")
        print("No DNS packets found.")
        return

    query_counts = Counter()
    qtype_counts = Counter()
    src_counts = Counter()
    base_domain_counts = Counter()
    unique_subdomains = defaultdict(set)
    suspicious = []
    txt_records = []

    for row in rows:
        qname = row.get("dns.qry.name", "").strip()
        qtype = row.get("dns.qry.type", "").strip()
        src = row.get("ip.src", "").strip()
        txt = row.get("dns.txt", "").strip()
        is_response = row.get("dns.flags.response", "").strip() == "1"

        if src:
            src_counts[src] += 1

        if qname and not is_response:
            query_counts[qname] += 1

            qtype_counts[qtype_name(qtype)] += 1

            bd = base_domain(qname)
            base_domain_counts[bd] += 1
            unique_subdomains[bd].add(qname)

            reasons = analyze_query_name(qname)
            if reasons:
                suspicious.append(
                    {
                        "frame": row.get("frame.number", ""),
                        "src": row.get("ip.src", ""),
                        "dst": row.get("ip.dst", ""),
                        "query": qname,
                        "reasons": reasons,
                    }
                )

        if txt:
            txt_records.append(
                {
                    "frame": row.get("frame.number", ""),
                    "src": row.get("ip.src", ""),
                    "dst": row.get("ip.dst", ""),
                    "txt": txt,
                }
            )

    print("=== DNS Analysis ===")
    print(f"DNS packets: {len(rows)}")

    print("\nTop DNS clients:")
    for src, count in src_counts.most_common(10):
        print(f"  {src:20} {count}")

    print("\nQuery types:")
    for qtype, count in qtype_counts.most_common():
        display = qtype if qtype else "unknown"
        print(f"  {display:8} {count}")

    print("\nTop queried names:")
    for query, count in query_counts.most_common(20):
        print(f"  {count:4}  {query}")

    print("\nTop base domains:")
    for domain, count in base_domain_counts.most_common(15):
        unique_count = len(unique_subdomains[domain])
        print(f"  {count:4} packets | {unique_count:4} unique | {domain}")
            