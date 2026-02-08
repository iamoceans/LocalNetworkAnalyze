# Local Network Analyzer

A Python-based desktop application for analyzing and monitoring local network traffic. Features real-time traffic monitoring, protocol parsing, anomaly detection, and data export capabilities.

## Features

- **Real-time Traffic Monitoring**: Capture and analyze network packets in real-time
- **Protocol Parsing**: Decode HTTP, DNS, TCP, UDP, and other protocols
- **LAN Scanning**: Discover devices on your local network
- **Anomaly Detection**: Identify suspicious network activity including:
  - Port scans
  - DDoS attacks
  - Traffic anomalies
- **Data Export**: Export analysis results to CSV, JSON, or PCAP formats
- **Modern GUI**: Built with CustomTkinter for a clean, modern interface

## Requirements

- Python 3.10+
- Administrator/root privileges (for packet capture)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/local-network-analyzer.git
cd local-network-analyzer
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

For development:
```bash
pip install -r requirements-dev.txt
```

## Usage

### Running the Application

```bash
python src/main.py
```

**Note**: On Linux/macOS, you may need to run with sudo:
```bash
sudo python src/main.py
```

### Command Line Options

```bash
# Use specific network interface
python src/main.py --interface eth0

# Set log level
python src/main.py --log-level DEBUG

# Load custom configuration
python src/main.py --config path/to/config.json
```

## Project Structure

```
LocalNetworkAnalyze/
├── src/
│   ├── core/          # Core infrastructure (config, logging, exceptions)
│   ├── capture/       # Packet capture module
│   ├── scan/          # Network scanning module
│   ├── protocol/      # Protocol parsing module
│   ├── analysis/      # Traffic analysis module
│   ├── detection/     # Anomaly detection module
│   ├── storage/       # Data storage module
│   ├── gui/           # Desktop GUI
│   └── utils/         # Utility functions
├── tests/             # Test suite
├── data/              # Data directory
└── logs/              # Application logs
```

## Configuration

The application can be configured via:

1. **JSON Configuration File**:
```json
{
  "capture": {
    "interface": "eth0",
    "filter": "",
    "buffer_size": 1000
  },
  "log": {
    "level": "INFO",
    "path": "logs/app.log"
  }
}
```

2. **Environment Variables**:
- `LNA_INTERFACE`: Network interface to use
- `LNA_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `LNA_DB_PATH`: Path to database file
- `LNA_THEME`: GUI theme (light, dark, system)

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
ruff check src/ tests/

# Type checking
mypy src/
```

## Architecture

The application follows these design principles:

- **Immutability**: All data classes use frozen dataclass
- **Small Files**: Each module is 200-400 lines max
- **Dependency Injection**: Components receive dependencies via constructor
- **Repository Pattern**: Data access abstracted behind repository interfaces
- **Factory Pattern**: Object creation decoupled via factory classes

## Security Considerations

- Requires administrator/root privileges for packet capture
- Only for use on networks you own or have permission to monitor
- Does not capture or store sensitive payload data by default
- Follow all applicable laws and regulations

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass and code is formatted
5. Submit a pull request

## Roadmap

- [ ] Web-based interface option
- [ ] Machine learning-based anomaly detection
- [ ] Support for more protocols
- [ ] Historical traffic analysis
- [ ] Report generation
- [ ] Plugin system for custom analyzers

## Troubleshooting

### "Permission denied" error
- Run with administrator/root privileges
- On Linux: Use `sudo`
- On Windows: Run as Administrator

### "No such device" error
- Check available interfaces with:
  - Linux: `ip link show`
  - macOS: `ifconfig`
  - Windows: `ipconfig`
- Use correct interface name in configuration

### High CPU usage
- Reduce buffer size in configuration
- Apply BPF filter to capture only relevant traffic
- Disable real-time visualization features

## Acknowledgments

Built with:
- [Scapy](https://scapy.net/) - Packet manipulation
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern GUI
- [Matplotlib](https://matplotlib.org/) - Data visualization
