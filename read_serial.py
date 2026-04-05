#!/usr/bin/env python3
import serial, time, sys

port = '/dev/ttyUSB0'
baud = 115200

try:
    ser = serial.Serial(port, baud, timeout=1)
except:
    print(f"ERROR: pyserial not installed or port busy. Try: pip install pyserial")
    sys.exit(1)

# Reset ESP32 via DTR/RTS
ser.dtr = False
ser.rts = False
time.sleep(0.1)
ser.dtr = True
ser.rts = True
time.sleep(0.1)
ser.dtr = False
ser.rts = False
print(f"--- ESP32 reset, reading {port} @ {baud} ---")

end = time.time() + 8
while time.time() < end:
    data = ser.read(ser.in_waiting or 1)
    if data:
        text = data.decode('utf-8', errors='replace')
        print(text, end='', flush=True)

ser.close()
print("\n--- Done ---")
