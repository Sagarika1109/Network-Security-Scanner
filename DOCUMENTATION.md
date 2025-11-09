# 🧠 Mini Network Security Scanner — Documentation

## Overview
The **Network Security Scanner** is a Python-based multi-threaded network analysis tool that identifies open ports, active services, and optionally retrieves service banners.  
It’s designed for **educational, ethical, and testing purposes only**, helping users understand how basic network enumeration works without introducing any security risks.

---

## Key Features
-  **Port Scanning:** Detects open ports on target hosts using socket connections.  
-  **Banner Grabbing (Optional):** Captures service banners for identification.  
-  **Multithreading:** Uses `ThreadPoolExecutor` for faster and efficient scanning.  
-  **Export Options:** Save results to CSV or JSON format.  
-  **Secure & Lightweight:** Uses only Python’s standard library — no external dependencies.

---

## Architecture & Design
The scanner consists of the following main components:
1. **`parse_ports()`** — Validates and prepares port lists from user input.
2. **`scan_port()`** — Establishes a TCP connection to a single port.
3. **`run_scan()`** — Manages multi-threaded scanning and output collection.
4. **`main()`** — Handles CLI arguments and orchestrates the full scan process.

---

## Security Considerations
- Input validation ensures ports are within safe ranges (1–65535).  
- Thread counts are capped to prevent accidental DoS conditions.  
- No external libraries, preventing supply-chain vulnerabilities.  
- All data access is local; no API calls or remote data storage.  
- The scanner does not perform exploits, brute force, or penetration actions.

---

## Example Usage
```bash
python3 scanner.py example.com --start 20 --end 100 --threads 100 --banner
```

Example Output:
```
[OPEN] Port 22 - SSH
[OPEN] Port 80 - HTTP (Banner: Apache/2.4.41)
[OPEN] Port 443 - HTTPS
```

---

## Limitations
- Designed for **authorized testing only**.
- Does not include exploit modules or privilege escalation features.
- Intended for learning and professional portfolio use.

---

## Author
**Sagarika Singh**  
📎 GitHub: [github.com/Sagarika1109](https://github.com/Sagarika1109)  
📧 Email: sagarikasingh1109@gmail.com  
💼 LinkedIn: www.linkedin.com/in/sagarika-singh-3111a7114
