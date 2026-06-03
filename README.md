# DPI Engine

A high-performance **Multi-Threaded Deep Packet Inspection (DPI) Engine** built in **Java 21** for network traffic analysis, application identification, traffic filtering, and PCAP processing.

The engine analyzes packet captures (PCAP files), reconstructs network flows, extracts application metadata, identifies traffic patterns, and applies configurable filtering rules in real time.

---

# Why DPI Engine?

Traditional packet filters only inspect packet headers.

DPI Engine goes further by inspecting packet payloads and protocol metadata to determine:

* Which applications generated the traffic
* Which domains were accessed
* Which connections belong to the same flow
* Which traffic should be blocked based on custom rules

This enables:

* Network Traffic Analysis
* Security Research
* Protocol Inspection
* Application Classification
* Rule-Based Traffic Filtering
* Educational Networking Experiments

---

# Key Features

## Packet Processing

* PCAP File Processing
* Ethernet Parsing
* IPv4 Parsing
* TCP Parsing
* UDP Parsing

## Traffic Identification

* TLS SNI Extraction
* DNS Query Extraction
* HTTP Host Header Extraction
* Application Detection

Supported applications include:

* YouTube
* GitHub
* Google
* Discord
* Netflix
* Facebook
* Telegram
* Spotify
* TikTok

## Connection Tracking

Stateful flow tracking using:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol

(Five-Tuple Flow Identification)

## Dynamic Rule Engine

External rule configuration without recompilation.

Supports:

* Domain Blocking
* Application Blocking
* IP Blocking
* Port Blocking

Example:

```text
BLOCK_DOMAIN=facebook.com
BLOCK_APP=YouTube
BLOCK_IP=8.8.8.8
BLOCK_PORT=443
```

## Multi-Threaded Processing

Producer-consumer architecture using:

* Load Balancer Threads
* Fast Path Processor Threads
* LinkedBlockingQueue
* Thread-safe Rule Management

Benefits:

* Higher Throughput
* Better CPU Utilization
* Scalable Packet Processing

## Analytics & Reporting

* Traffic Statistics
* Application Statistics
* Domain Statistics
* Connection Statistics
* Rule Statistics

---

# System Architecture

```text
                    +------------------+
                    |    PCAP Reader   |
                    +------------------+
                              |
                              v
                    +------------------+
                    |  Load Balancers  |
                    +------------------+
                              |
          +-------------------+-------------------+
          |                                       |
          v                                       v
 +------------------+                 +------------------+
 | Fast Path Proc 1 |                 | Fast Path Proc N |
 +------------------+                 +------------------+
          |                                       |
          +-------------------+-------------------+
                              |
            +-----------------+-----------------+
            |                                   |
            v                                   v
 +---------------------+          +---------------------+
 | Connection Tracking |          |    Rule Engine      |
 +---------------------+          +---------------------+
            |                                   |
            +-----------------+-----------------+
                              |
                              v
                    +------------------+
                    |    PCAP Writer   |
                    +------------------+
                              |
                              v
                    +------------------+
                    | Traffic Reports  |
                    +------------------+
```

---

# Packet Processing Pipeline

```text
Raw Packet
    |
    v
Ethernet Parser
    |
    v
IPv4 Parser
    |
    v
TCP / UDP Parser
    |
    v
Protocol Inspection
    |
    +---- TLS SNI Extraction
    |
    +---- DNS Extraction
    |
    +---- HTTP Host Extraction
    |
    v
Application Identification
    |
    v
Rule Evaluation
    |
    v
Forward / Block
```

---

# Dynamic Rule Engine (v1.1)

The Dynamic Rule Engine allows traffic filtering through an external rules file.

## Supported Rules

### Domain Rules

```text
BLOCK_DOMAIN=facebook.com
BLOCK_DOMAIN=instagram.com
```

Matches:

```text
www.facebook.com
m.facebook.com
api.facebook.com
```

### Application Rules

```text
BLOCK_APP=YouTube
BLOCK_APP=TikTok
```

### IP Rules

```text
BLOCK_IP=8.8.8.8
```

### Port Rules

```text
BLOCK_PORT=443
```

---

# Example Rules File

```text
# Social Media
BLOCK_DOMAIN=facebook.com
BLOCK_DOMAIN=instagram.com

# Video Streaming
BLOCK_APP=YouTube
BLOCK_APP=TikTok

# DNS Servers
BLOCK_IP=8.8.8.8

# HTTPS
BLOCK_PORT=443
```

---

# Project Structure

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
│   ├── RuleManager.java
│   └── RuleFileParser.java
│
├── tracking
│   ├── ConnectionTracker.java
│   └── GlobalConnectionTable.java
│
└── types
    ├── FiveTuple.java
    ├── ParsedPacket.java
    ├── Connection.java
    ├── PacketJob.java
    └── DPIStats.java
```

---

# Build

## Prerequisites

* Java 21
* Maven 3.9+

## Compile

```bash
mvn clean package
```

---

# Usage

## Basic Execution

```bash
java -jar target/dpi-engine-1.0-SNAPSHOT.jar input.pcap output.pcap
```

## Rule Engine Execution

```bash
java -jar target/dpi-engine-1.0-SNAPSHOT.jar \
input.pcap \
output.pcap \
-r rules.txt \
-v
```

---

# Example Output

```text
==================================================
RULE ENGINE
==================================================

Loaded Rules:
Domains: 2
IPs: 1
Ports: 1
Applications: 2

==================================================
```

```text
[BLOCKED]

Flow:
192.168.1.100:64044
-> www.facebook.com

Rule:
BLOCK_DOMAIN=facebook.com
```

```text
==================================================
RULE STATISTICS
==================================================

Blocked By Domain: 12
Blocked By IP: 4
Blocked By Port: 20
Blocked By Application: 17

Total Blocked Flows: 53

==================================================
```

---

# Technologies Used

* Java 21
* Maven
* Concurrent Collections
* LinkedBlockingQueue
* ReentrantReadWriteLock
* AtomicLong
* PCAP Parsing
* Multi-threading

---

# Performance Characteristics

Current implementation supports:

* Multi-threaded Packet Processing
* Concurrent Flow Tracking
* Lock-protected Rule Management
* High-throughput Traffic Analysis
* Stateful Connection Tracking

---

# Roadmap

## ✅ v1.0 – Core DPI Engine

* PCAP Processing
* TCP/UDP Parsing
* SNI Extraction
* Connection Tracking
* Multi-threaded Pipeline

## ✅ v1.1 – Dynamic Rule Engine

* External Rule Configuration
* Domain Filtering
* IP Filtering
* Port Filtering
* Application Filtering
* Verbose Blocking Logs
* Rule Statistics
* Subdomain-aware Domain Matching

## 🚧 v1.2 – Analytics Export

Planned:

* CSV Reports
* JSON Reports
* Application Usage Analytics
* Domain Analytics Export

## 🚧 v1.3 – Performance Dashboard

Planned:

* Throughput Metrics
* Memory Usage Tracking
* Processing Statistics
* Runtime Monitoring

---

# Learning Outcomes

This project demonstrates practical experience with:

* Computer Networks
* Protocol Analysis
* TCP/IP Internals
* Deep Packet Inspection
* Concurrent Programming
* Producer-Consumer Architecture
* Thread Synchronization
* System Design
* Performance Engineering
* Java Backend Development

---

# License

This project is intended for educational, research, and networking experimentation purposes.
