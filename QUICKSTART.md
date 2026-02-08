# Quick Start Guide

## First Time Setup

### Windows
1. Double-click `start.bat` OR
2. Open Command Prompt and run:
   ```bash
   start.bat
   ```

### Linux/Mac
1. Make script executable:
   ```bash
   chmod +x start.sh
   ```
2. Run with sudo:
   ```bash
   sudo ./start.sh
   ```

## Common Commands

### Start GUI Application
```bash
python run.py
```

### Headless Capture (60 seconds)
```bash
python -m src.main --headless --interface eth0 --duration 60
```

### Network Scan (ARP)
```bash
python -m src.main --scan arp --target 192.168.1.0/24
```

### Run Tests
```bash
pytest tests/unit/ -v
```

## Troubleshooting

### "Permission denied" when capturing
**Windows**: Right-click and "Run as Administrator"
**Linux/Mac**: Use `sudo`

### "No module named 'scapy'"
```bash
pip install scapy customtkinter matplotlib sqlalchemy
```

### GUI doesn't appear
- Install CustomTkinter: `pip install customtkinter>=5.2.0`
- Falls back to standard tkinter automatically

## Features Overview

| Panel | Description |
|-------|-------------|
| Dashboard | Real-time traffic stats, bandwidth, protocol distribution |
| Capture | Start/stop packet capture with filters |
| Scan | Network discovery (ARP/ICMP) and port scanning |
| Analysis | Query and analyze captured traffic |
| Alerts | View and manage security alerts |

## Keyboard Shortcuts (GUI)

- **Sidebar buttons**: Navigate between panels
- **Start/Stop**: Control packet capture
- **Clear**: Clear displayed data
- **Save**: Export data to file
- **Exit**: Close application (cleanup automatically)

## Data Location

- **Database**: `data/network_analyzer.db` (auto-created)
- **Logs**: `logs/` directory (if configured)
