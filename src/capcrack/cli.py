import argparse
from pathlib import Path

from capcrack.modules.summary import run_summary
from capcrack.modules.dns import run_dns


def main():
    parser = argparse.ArgumentParser(
        prog="capcrack",
        description="CTF-focused PCAP triage helper",
    )

    # parser.add_argument(
        #     "--version",
        #     action="version",
        #     version="capcrack 0.1.0",
        # )

    subparsers = parser.add_subparsers(dest="command", required=True)

    summary_parser = subparsers.add_parser(
        "summary",
        help="Show basic PCAP summary",
    )
    summary_parser.add_argument(
        "pcap",
        type=Path
    )

    dns_parser = subparsers.add_parser(
        "dns",
        help="Analyze DNS traffic",
    )
    dns_parser.add_argument(
        "pcap",
        type=Path
    )

    args = parser.parse_args()

    if args.command == "summary":
        run_summary(args.pcap)

    if args.command == "dns":
        run_dns(args.pcap)

    
if __name__ == "__main__":
    main()