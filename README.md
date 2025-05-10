
# Network Traffic Analyzer

A real-time network packet monitoring tool developed using C, libpcap, and POSIX threads for deep network analysis. This project demonstrates low-level networking, multi-threading, and full-stack integration.

## Features

- **Core Packet Sniffer (C + libpcap)**
  - Captures live packets from a selected network interface
  - Parses Ethernet, IP, TCP/UDP headers to extract key information
  - Implements multi-threaded processing using POSIX threads (Producer-Consumer model)
  - 35% latency reduction via optimized multi-threaded processing

- **Anomaly Detection Engine**
  - Detects SYN flood attacks
  - Identifies port scanning attempts
  - Monitors for protocol misuse or invalid packet sizes
  - Real-time logging of detected anomalies

- **Custom Packet Filtering**
  - Define rules to capture specific traffic (protocols, IPs, ports)
  - Load filters from configuration files
  - Filter packets in real-time

- **Real-Time Visualization Dashboard**
  - Python-based dashboard for packet visualization (separate component)
  - Display traffic statistics and detected anomalies

## Installation

### Prerequisites

- Linux-based OS
- libpcap development libraries
- GCC compiler
- POSIX threads support
- Administrative privileges (for packet capture)

### Build Instructions

1. Install dependencies:
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev build-essential
=======

