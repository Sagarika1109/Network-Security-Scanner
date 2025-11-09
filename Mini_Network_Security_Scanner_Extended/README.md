# FILE: README.md

##  Mini Network Security Scanner (Extended)

A Python-based **multi-threaded network scanner** that identifies open ports, detects running services, and optionally grabs service banners. Supports flexible port ranges, CSV/JSON export, and detailed progress reporting.

---

### Features
- Multithreaded port scanning using `ThreadPoolExecutor`
- Optional **banner grabbing** for service identification
- Save scan results to **CSV** or **JSON**
- Customizable port ranges, thread count, and timeouts
- CLI-based with verbose progress output
- Cross-platform and safe to import in tests

---

### Installation
```bash
git clone https://github.com/yourusername/network-security-scanner.git
cd network-security-scanner
python3 -m venv venv
source venv/bin/activate  # or venv\\Scripts\\activate on Windows
```

No external dependencies required beyond the Python standard library.

---

###  Usage Examples
#### Basic Scan
```bash
python3 scanner.py 192.168.1.10
```

#### Scan a Range of Ports
```bash
python3 scanner.py example.com --start 1 --end 1024 --threads 200
```

#### Custom Ports and Banner Grabbing
```bash
python3 scanner.py example.com --ports 22,80,443 --banner --timeout 1.0
```

#### Save Output to File
```bash
python3 scanner.py 192.168.1.15 --ports 20-25,80,443 --output results.csv
```

---

###  Output Example
```
Scan complete for example.com (93.184.216.34)
Duration: 5.42s | Open ports: 3
[OPEN] Port 22 -> SSH
[OPEN] Port 80 -> HTTP | Banner: HTTP/1.0 200 OK
[OPEN] Port 443 -> HTTPS
Report saved to results.csv
```

---

### 🧪 Running Tests
You can test the core functions manually:
```python
from scanner import parse_ports, run_scan
ports = parse_ports('22,80,443', 1, 65535)
report = run_scan('scanme.nmap.org', ports, threads=50, timeout=1, banner=False)
print(report)
```

---

### 📁 Project Structure
```
├── scanner.py        # Main scanner script
├── README.md         # Documentation
├── .gitignore        # Ignore unnecessary files
└── sample_reports/   # Optional output examples
```

---

###  Author
**Sagarika Singh**  
http://www.linkedin.com/in/sagarika-singh-3111a7114 • http://www.linkedin.com/in/sagarika-singh-3111a7114

---

### ⚙️ License
MIT License © 2025 Sagarika Singh

---

### 💡 Note
The project is educational - a starting point for learning **socket programming**, **network enumeration**, and **multithreading** in Python.

---

### 🧾 .gitignore 
Create a `.gitignore` file in the project root with the following:
```bash
# Virtual environment
venv/

# Python cache files
__pycache__/
*.pyc
*.pyo
*.pyd

# IDE settings
.vscode/
.idea/

# OS-specific files
.DS_Store
Thumbs.db

# Output and logs
*.log
sample_reports/*.csv
sample_reports/*.json
```
