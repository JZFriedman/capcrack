# capcrack

A CTF-focused PCAP triage helper.

## Goal

`capcrack` helps quickly identify interesting network traffic in packet captures:
DNS queries, HTTP requests, credentials, suspicious streams, files, and possible flags.

## Requirements

- Python 3.10+
- TShark / Wireshark CLI tools

## Install

```bash
git clone https://github.com/JZFriedman/capcrack.git
cd capcrack
python3 -m venv .venv
source .venv/bin/activate
pip install -e .