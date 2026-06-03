# DPI Engine

Multi-threaded Deep Packet Inspection (DPI) Engine built in Java 21 for network traffic analysis, application identification, and PCAP processing.

## Overview

DPI Engine analyzes network traffic captured in PCAP files and performs Deep Packet Inspection to identify applications, extract domains, track connections, and generate traffic analytics.

Unlike traditional packet filters that only inspect headers, DPI Engine examines protocol payloads to classify traffic and detect applications such as YouTube, GitHub, Discord, Netflix, Google, Facebook, Telegram, and more.

### Key Capabilities

* PCAP File Processing
* TCP/UDP Packet Parsing
* TLS SNI Extraction
* DNS Domain Extraction
* Connection Tracking
* Application Identification
* Multi-threaded Packet Processing
* Traffic Statistics & Reporting
* Rule-Based Traffic Filtering

---

## Architecture

```text
                PCAP Reader
                     │
                     ▼
             Load Balancers
                     │
                     ▼
          Fast Path Processors
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
 Connection Tracking       Rule Engine
        │                         │
        └────────────┬────────────┘
                     ▼
               PCAP Writer
                     │
                     ▼
             Traffic Reports
```

---

## Features

### Packet Parsing

The engine parses multiple protocol layers:

* Ethernet
* IPv4
* TCP
* UDP

Extracted information includes:

* Source/Destination IP
* Source/Destination Port
* Protocol Type
* Packet Metadata

---

### Application Identification

Applications are identified using:

#### TLS SNI Inspection

Extracts Server Name Indication (SNI) from TLS Client Hello packets.

Examples:

```text
www.youtube.com  → YouTube
github.com       → GitHub
discord.com      → Discord
```

#### DNS Inspection

Extracts queried domains from DNS traffic.

---

### Connection Tracking

Each network flow is tracked using a Five-Tuple:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

This enables stateful traffic analysis and accurate application classification.

---

### Multi-threaded Processing

The engine uses a producer-consumer architecture:

* Load Balancer Threads
* Fast Path Processing Threads
* Thread-safe Queues

Benefits:

* Improved throughput
* Better CPU utilization
* Scalable packet processing

---

## Project Structure

```text
src/main/java/com/packetanalyzer
│
├── engine
│   ├── DpiEngine.java
│   ├── LoadBalancer.java
│   └── FastPathProcessor.java
│
├── parser
│   └── PacketParser.java
│
├── extractors
│   ├── SniExtractor.java
│   ├── DnsExtractor.java
│   └── HttpHostExtractor.java
│
├── io
│   ├── PcapReader.java
│   ├── PcapWriter.java
│   └── ByteUtils.java
│
├── rules
│   └── RuleManager.java
│
├── tracking
│   ├── ConnectionTracker.java
│   └── GlobalConnectionTable.java
│
└── types
    ├── FiveTuple.java
    ├── ParsedPacket.java
    ├── Connection.java
    └── DPIStats.java
```

---

## Sample Execution

```bash
java -jar target/dpi-engine-1.0-SNAPSHOT.jar input.pcap output.pcap
```

### Sample Output

```text
Total Packets:      77
TCP Packets:        73
UDP Packets:         4

Active Connections: 43

Applications:
- GitHub
- Google
- YouTube
- Discord
- Netflix
- Telegram
- Spotify
```

---

## Technologies Used

* Java 21
* Maven
* Concurrent Collections
* LinkedBlockingQueue
* ReentrantReadWriteLock

---

## Performance

Current implementation supports:

* Multi-threaded packet processing
* Concurrent flow tracking
* Efficient PCAP parsing
* High-throughput traffic analysis

---

## Roadmap

### v1.0 - Core DPI Engine

* PCAP Processing
* TCP/UDP Parsing
* SNI Extraction
* Connection Tracking
* Multi-threaded Pipeline

### v1.1 - Dynamic Rule Engine

* External rule configuration
* Domain/IP/Application filtering

### v1.2 - Analytics Export

* CSV Reports
* JSON Reports

### v1.3 - Performance Dashboard

* Throughput Metrics
* Memory Usage Tracking
* Processing Statistics

---

## Learning Outcomes

This project demonstrates:

* Computer Networks
* Protocol Analysis
* Concurrent Programming
* Producer-Consumer Architecture
* Packet Processing Systems
* Java Performance Optimization
* System Design

---

## License

This project is intended for educational and research purposes.
