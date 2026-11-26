# ⚡ PYSCAN — Python Network Scanner

<p align="center">
  <b>A Lightweight TCP Network & Port Scanner Built Entirely With Python</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-00FF41?style=for-the-badge&labelColor=000000"/>
  <img src="https://img.shields.io/badge/Dependencies-Standard%20Library-00FF41?style=for-the-badge&labelColor=000000"/>
  <img src="https://img.shields.io/badge/License-MIT-00FF41?style=for-the-badge&labelColor=000000"/>
</p>

## About

PYSCAN is a lightweight network and TCP port scanning tool developed using Python's standard library.

It provides basic host discovery, TCP connect scanning, service identification, banner detection, and structured scan reports.

## Features

- Host discovery using ICMP and TCP connectivity checks
- TCP connect port scanning
- Common port scanning
- Custom port lists and ranges
- CIDR and IP range parsing
- Multithreaded scanning
- Basic service identification
- Banner detection
- JSON output
- CSV output
- Scan results saved to files
- IPv4 and IPv6 support where implemented

## Technology

- Python
- Socket Programming
- ThreadPoolExecutor
- IP Address Processing
- JSON and CSV

## Installation

Clone the repository:

```bash
git clone https://github.com/Roger656ef/PYSCAN.git
```

Enter the directory:

```bash
cd PYSCAN
```

No third-party packages are required.

## Usage

Display help:

```bash
python pyscan.py --help
```

Scan localhost:

```bash
python pyscan.py 127.0.0.1
```

Scan selected ports:

```bash
python pyscan.py 127.0.0.1 -p 22,80,443
```

Scan a port range:

```bash
python pyscan.py 127.0.0.1 -p 1-1024
```

Export JSON:

```bash
python pyscan.py 127.0.0.1 --json -o results.json
```

Export CSV:

```bash
python pyscan.py 127.0.0.1 --csv -o results.csv
```

## Limitations

- TCP connect scanning only.
- No SYN scanning.
- No UDP scanning.
- No operating system fingerprinting.
- Service identification is heuristic-based.
- Banner detection is best-effort.

## Responsible Use

Use PYSCAN only on systems and networks you own or have explicit authorization to assess.

## Author

**Roger656ef**

Cybersecurity Researcher | VAPT

GitHub: https://github.com/Roger656ef

## License

MIT License
