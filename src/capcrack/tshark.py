import csv
import shutil
import subprocess
import sys


def require_shark():
    if shutil.which("tshark") is None:
        print("[-] tshark not found. Install Wireshark/TShark first.", file=sys.stderr)
        sys.exit(1)


def run_tshark(pcap, fields, display_filter=None):
    require_shark()

    cmd = [
        "tshark",
        "-r", str(pcap),
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]

    if display_filter:
        cmd += ["-Y", display_filter]

    for field in fields:
        cmd += ["-e", field]

    result = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    
    lines = result.stdout.splitlines()
    if not lines:
        return []
    
    return list(csv.DictReader(lines, delimiter="\t"))