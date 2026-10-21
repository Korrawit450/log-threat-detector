# Web Access Log Threat Detector

A defensive security utility written in Python that analyzes web server access logs (Nginx/Apache) to detect signs of reconnaissance, injection attempts, and suspicious request volume.

## Features
- **Attack Signature Detection:** Identifies indicators of Path Traversal, SQL Injection, Cross-Site Scripting (XSS), and sensitive configuration file probing.
- **Volume Profiling:** Aggregates request counts per IP address to highlight potential brute-force or denial-of-service patterns.
- **Zero Heavy Dependencies:** Built around Python's native regular expression and parsing capabilities.

## Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/](https://github.com/)<YOUR_USERNAME>/log-threat-detector.git
   cd log-threat-detector