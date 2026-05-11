import argparse
from pathlib import Path

from capcrack.modules.summary import run_summary


def main():
    parser = argparse.ArgumentParser(
        prog="capcrack",
        description="CTF-focused PCAP triage helper",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    summary_parser = subparsers.add_parser("summary", help="Show basic PCAP summary")
    summary_parser.add_argument("pcap", type=Path)

    args = parser.parse_args()

    if args.command == "summary":
        run_summary(args.pcap)

    
if __name__ == "__main__":
    main()