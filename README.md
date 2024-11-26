# HTTP Packet Reconstruction Tool

This Python script analyzes a PCAP file to extract and reconstruct HTTP packets. It identifies packets containing HTTP requests or responses and displays key information such as source/destination IPs, ports, and the HTTP payload.

## Features
- Extracts HTTP data from packets in a PCAP file.
- Identifies packets containing HTTP requests (e.g., GET, POST).
- Reconstructs and prints HTTP packet details.

## Requirements
- Python 3.6 or higher
- `scapy` library

Install the `scapy` library using pip:
```bash
pip install scapy
```

## Usage

1. Ensure you have a PCAP file (e.g., `captured_traffic.pcap`) containing network traffic.
2. Place the script and the PCAP file in the same directory.
3. Run the script:

```bash
python main.py
```

The script will process the packets in the specified PCAP file and reconstruct the first HTTP packet it encounters.

## Customization
- To analyze a specific PCAP file, modify the `pcap_file` variable in the script:
  ```python
  pcap_file = 'captured_traffic.pcap'
  ```

- To process all HTTP packets instead of stopping after the first, remove or modify the `break` statement in the `main` function.

