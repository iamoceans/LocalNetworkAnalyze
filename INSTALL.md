# Installation Guide

Local Network Analyzer requires specific dependencies to capture network traffic on Windows systems.

## Prerequisites

### 1. Python Requirements

- Python 3.8 or higher
- pip package manager

### 2. Npcap (Required for Windows)

**Npcap is the Windows packet capture library required by this application.**

#### Download Npcap

Visit the official Npcap website: https://npcap.com/

Or download directly from: https://npcap.com/dist/npcap-1.80.exe

#### Installation Steps

1. **Download the Npcap installer** from the link above

2. **Run the installer as Administrator**:
   - Right-click the installer
   - Select "Run as administrator"

3. **IMPORTANT: Select the correct options**:
   - ✅ **Check "Install Npcap in WinPcap API-compatible Mode"**
   - This option is critical for compatibility with Scapy
   - Optionally check "Support raw 802.11 traffic" if you need wireless monitoring

4. **Complete the installation** and restart your computer

#### Verify Npcap Installation

Open Command Prompt and run:

```cmd
sc query npcap
```

You should see:
```
SERVICE_NAME: npcap
        STATE              : RUNNING
```

## Running the Application

### Method 1: Using Command Line

1. **Open Command Prompt as Administrator**:
   - Press `Win + X`
   - Select "Terminal (Admin)" or "Command Prompt (Admin)"

2. **Navigate to the project directory**:
   ```cmd
   cd D:\work_space\LocalNetworkAnalyze
   ```

3. **Run the application**:
   ```cmd
   python src/main.py
   ```

### Method 2: Using Python Script

1. **Right-click on `src/main.py`**
2. **Select "Run with Python"**
3. **If prompted, run as Administrator**

## Common Issues and Solutions

### Issue 1: "Permission denied" or "Administrator privileges required"

**Cause**: Application is running without administrator privileges.

**Solution**:
- Always run the application as Administrator
- Right-click the application and select "Run as administrator"

### Issue 2: "Npcap not installed" or "socket error"

**Cause**: Npcap is not installed or not properly configured.

**Solution**:
1. Install Npcap following the steps above
2. Ensure you selected "Install Npcap in WinPcap API-compatible Mode"
3. Restart your computer after installation
4. Run the application as Administrator

### Issue 3: "No suitable network interface found"

**Cause**: No active network interface detected.

**Solution**:
1. Ensure you have an active network connection (Wi-Fi or Ethernet)
2. Disconnect any VPN connections temporarily
3. Refresh the interface list in the application

### Issue 4: "Npcap service is not running"

**Cause**: Npcap service failed to start.

**Solution**:
1. Open Command Prompt as Administrator
2. Run: `net start npcap`
3. If the service fails to start, reinstall Npcap

## Development Setup

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Main Dependencies

```
scapy>=2.5.0
customtkinter>=5.2.0
psutil>=5.9.0
```

## Troubleshooting

### Check Environment Status

The application includes an environment checker. Run the following to check your setup:

```python
python -c "from src.capture.scapy_capture import ScapyCapture; result = ScapyCapture.check_capture_environment(); print(result)"
```

### Enable Debug Logging

Run the application with debug mode:

```bash
python src/main.py --debug
```

Check the log file at `logs/app.log` for detailed error messages.

## Additional Resources

- **Npcap Website**: https://npcap.com/
- **Scapy Documentation**: https://scapy.readthedocs.io/
- **Project Repository**: https://github.com/your-repo

## Uninstallation

### Remove Npcap

1. Open "Programs and Features" in Windows Control Panel
2. Find "Npcap"
3. Right-click and select "Uninstall"

## Support

If you encounter issues not covered in this guide:

1. Check the log file at `logs/app.log`
2. Run the application with `--debug` flag
3. Review the error messages in the application
4. Ensure all prerequisites are met

## Security Note

This application captures network traffic for analysis purposes. Always:
- Run with appropriate permissions only
- Use network monitoring responsibly
- Comply with local laws and regulations
- Only monitor networks you own or have permission to monitor
