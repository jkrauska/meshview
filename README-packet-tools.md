# Packet Inspection Tools

This document describes standalone CLI tools for inspecting and analyzing packet data from the Meshview SQLite database.

## inspect_packets.py

A standalone CLI tool to inspect packets from the database without running the full web server. The tool opens the database in read-only mode and decodes protobuf payloads to display human-readable information.

### Features

- **Read-only database access** - Safe to run while Meshview is running
- **Protobuf decoding** - Automatically decodes all major Meshtastic packet types
- **Flexible filtering** - Filter by port number, node ID, or packet count
- **Broadcast detection** - Properly identifies broadcast messages (0xffffffff)
- **Detailed output** - Shows node names, positions, telemetry, and more

### Installation

The tool uses the same dependencies as Meshview. Ensure you have activated the virtual environment:

```bash
source env/bin/activate
```

### Usage

#### Basic Usage

```bash
# Inspect last 100 packets (default)
./env/bin/python inspect_packets.py packets.db

# Inspect last 50 packets
./env/bin/python inspect_packets.py packets.db -n 50

# Inspect last 10 packets
./env/bin/python inspect_packets.py packets.db -n 10
```

#### Filtering by Port Number

```bash
# Show only text messages
./env/bin/python inspect_packets.py packets.db --portnum 1

# Show only position updates
./env/bin/python inspect_packets.py packets.db --portnum 3

# Show only telemetry data
./env/bin/python inspect_packets.py packets.db --portnum 67

# Show only routing packets
./env/bin/python inspect_packets.py packets.db --portnum 6
```

#### Filtering by Node

```bash
# Show packets from/to a specific node (hex format)
./env/bin/python inspect_packets.py packets.db --node 0x123456

# Show packets from/to a specific node (decimal format)
./env/bin/python inspect_packets.py packets.db --node 1193046

# Exclude packets from/to a specific node
./env/bin/python inspect_packets.py packets.db --exclude-node 0x123456

# Combine: show text messages but exclude a specific node
./env/bin/python inspect_packets.py packets.db --portnum 1 --exclude-node 0xffffffff
```

#### Combining Filters

```bash
# Last 20 text messages
./env/bin/python inspect_packets.py packets.db --portnum 1 -n 20

# Last 10 packets from a specific node
./env/bin/python inspect_packets.py packets.db --node 0x123456 -n 10
```

#### JSON Output

The tool provides beautifully formatted JSON output with automatic syntax highlighting when outputting to a terminal.

```bash
# Get packets in JSON format (with color syntax highlighting in terminal)
./env/bin/python inspect_packets.py packets.db --json

# Get last 10 text messages as JSON
./env/bin/python inspect_packets.py packets.db --portnum 1 -n 10 --json

# Pipe to file (colors automatically disabled)
./env/bin/python inspect_packets.py packets.db --json > output.json

# Pipe to jq for advanced filtering
./env/bin/python inspect_packets.py packets.db --json | jq '.packets[0]'
```

**Note:** Color syntax highlighting is automatically enabled when outputting to a terminal and disabled when piping to files or other commands. This uses the `pygments` library for beautiful, readable JSON output.

#### Getting Help

```bash
./env/bin/python inspect_packets.py --help
```

### Port Numbers Reference

| Port | Name | Description |
|------|------|-------------|
| 0 | UNKNOWN_APP | Unknown application |
| 1 | TEXT_MESSAGE_APP | Text messages |
| 3 | POSITION_APP | GPS position updates |
| 4 | NODEINFO_APP | Node information (name, hardware) |
| 6 | ROUTING_APP | Routing control messages |
| 67 | TELEMETRY_APP | Telemetry data (battery, sensors) |
| 70 | TRACEROUTE_APP | Network traceroute data |
| 71 | NEIGHBORINFO_APP | Neighbor discovery information |

### Example Output

```
================================================================================
Found 3 packet(s)
================================================================================

Packet #1 (ID: 1907555120)
────────────────────────────────────────────────────────────────────────────────
Time: 2025-10-02 10:57:28.002023
Port: TELEMETRY_APP (67)
From: LMF1🌳 (LMF1) [3265474337 / 0xc2992721]
To: Broadcast [4294967295 / 0xffffffff]
Channel: MediumFast

Decoded Payload:
  Telemetry:
    Battery: 89%
    Voltage: 4.045000076293945V
    Channel Utilization: 1.159999966621399%
    Air Utilization TX: 0.3701944351196289%

================================================================================

Packet #2 (ID: 3676545452)
────────────────────────────────────────────────────────────────────────────────
Time: 2025-10-02 10:57:24.344317
Port: NODEINFO_APP (4)
From: DATA YXW (DATA) [1129850416 / 0x43596630]
To: Broadcast [4294967295 / 0xffffffff]
Channel: MediumSlow

Decoded Payload:
  Node Info:
    Long Name: DATA YXW
    Short Name: DATA
    Hardware: 43

================================================================================

Packet #3 (ID: 1473436921)
────────────────────────────────────────────────────────────────────────────────
Time: 2025-10-02 10:57:18.128995
Port: TEXT_MESSAGE_APP (1)
From: MKB Actual @ Baymesh (🐵) [1259833802 / 0x4b1b65ca]
To: Broadcast [4294967295 / 0xffffffff]
Channel: MediumSlow

Decoded Payload:
  Text Message:
    Size: 10 bytes
    Message: OM NOM NOM

================================================================================
```

### Decoded Payload Types

#### Text Messages (Port 1)
- Displays the message content with byte size on separate lines
- Example:
  ```
  Text Message:
    Size: 200 bytes
    Message: Your message here
  ```

#### Position Updates (Port 3)
- Latitude and longitude (in decimal degrees)
- Altitude (in meters)

#### Node Info (Port 4)
- Long name
- Short name
- Hardware model number

#### Telemetry (Port 67)
- **Device Metrics:**
  - Battery level (%)
  - Voltage (V)
  - Channel utilization (%)
  - Air utilization TX (%)
- **Environment Metrics:**
  - Temperature (°C)
  - Humidity (%)
  - Barometric pressure (hPa)

#### Traceroute (Port 70)
- Route path showing node IDs in hop sequence

#### Neighbor Info (Port 71)
- List of neighboring nodes
- Signal-to-Noise Ratio (SNR) for each neighbor

#### Routing (Port 6)
- Error messages if routing failed

### Command-line Options

```
usage: inspect_packets.py [-h] [-n COUNT] [-p PORTNUM] [--node NODE] [database]

positional arguments:
  database              Path to the SQLite database file (default: packets.db)

options:
  -h, --help            show this help message and exit
  -n, --count COUNT     Number of packets to retrieve (default: 100)
  -p, --portnum PORTNUM
                        Filter by port number (e.g., 1 for TEXT_MESSAGE_APP)
  --node NODE           Filter by node ID (from or to), supports hex (0x123) or decimal
  --exclude-node NODE   Exclude packets from/to node ID, supports hex (0x123) or decimal
  --json                Output in JSON format
```

### Notes

- The tool opens the database in read-only mode, so it's safe to use while Meshview is running
- Node IDs can be specified in either hexadecimal (0x123456) or decimal (1193046) format
- Broadcast messages are sent to 0xffffffff and displayed as "Broadcast" in the To field
- The tool requires the same Python environment and dependencies as the main Meshview application
