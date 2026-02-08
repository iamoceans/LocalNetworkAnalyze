#!/bin/bash
# Local Network Analyzer - Linux/Mac Startup Script
# Run this script to start the application

echo "Starting Local Network Analyzer..."
echo ""

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
else
    echo "No virtual environment found."
    echo "Creating one now..."
    python3 -m venv venv
    source venv/bin/activate
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Check for root privileges
if [ "$EUID" -eq 0 ]; then
    echo "Running with root privileges - OK"
else
    echo "WARNING: Not running as root."
    echo "Packet capture may not work correctly."
    echo "Run with: sudo ./start.sh"
    echo ""
fi

# Start the application
echo ""
echo "Starting GUI application..."
python run.py
