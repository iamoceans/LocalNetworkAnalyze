"""
Debug script to check CapturePanel UI build.
"""

import tkinter as tk
from src.capture import create_capture as create_packet_capture
from src.gui.capture_panel import create_capture_panel

# Create capture engine
print("Creating capture engine...")
capture = create_packet_capture(backend="scapy")
print("✓ Capture engine created")

# Create a test window
print("\nCreating test window...")
root = tk.Tk()
root.title("Capture Panel Debug")
root.geometry("1000x700")

# Create capture panel
print("Creating capture panel...")
panel = create_capture_panel(
    parent=root,
    capture=capture,
    analysis=None,
    detection=None,
    database=None,
)

# Build panel UI
print("Building panel UI...")
frame = panel.build()

# Check if widgets exist
print("\nChecking widgets...")
print(f"  Frame created: {panel._frame is not None}")
print(f"  Control frame created: {panel._control_frame is not None}")
print(f"  Start button created: {panel._start_button is not None}")
print(f"  Stop button created: {panel._stop_button is not None}")
print(f"  Clear button created: {panel._clear_button is not None}")
print(f"  Save button created: {panel._save_button is not None}")
print(f"  Interface combo created: {panel._interface_combo is not None}")
print(f"  Packet tree created: {hasattr(panel, '_packet_tree')}")

# Check button states
if panel._start_button:
    print(f"\n  Start button state: {panel._start_button['state']}")
if panel._stop_button:
    print(f"  Stop button state: {panel._stop_button['state']}")

# Check frame children
print("\nFrame widget hierarchy:")
def print_widget_hierarchy(widget, indent=0):
    try:
        children = widget.winfo_children()
        print(f"{'  ' * indent}{widget.winfo_class()}: {widget.winfo_name()}")
        for child in children:
            print_widget_hierarchy(child, indent + 1)
    except Exception as e:
        print(f"{'  ' * indent}Error: {e}")

print_widget_hierarchy(frame)

print("\n✓ Debug complete. Window should be visible.")
print("  Check if you can see the control buttons.")
print("\nPress Ctrl+C to exit or close the window.")

try:
    root.mainloop()
except KeyboardInterrupt:
    print("\nExiting...")
