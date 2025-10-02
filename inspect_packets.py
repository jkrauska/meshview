#!/usr/bin/env python3
"""
Standalone CLI tool to inspect packets from the Meshview SQLite database.
Reads the last N packets and decodes their protobuf payloads.
"""

import asyncio
import argparse
import sys
import json
from datetime import datetime
from pathlib import Path

try:
    from pygments import highlight
    from pygments.lexers import JsonLexer
    from pygments.formatters import TerminalFormatter
    PYGMENTS_AVAILABLE = True
except ImportError:
    PYGMENTS_AVAILABLE = False


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Bright colors
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_MAGENTA = '\033[95m'


def colorize(text, color, bold=False):
    """Add color to text if output is a TTY."""
    if sys.stdout.isatty():
        prefix = Colors.BOLD if bold else ''
        return f"{prefix}{color}{text}{Colors.RESET}"
    return text

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Import meshview modules
from meshview.models import Packet, Node
from meshview.decode_payload import decode
from meshtastic.protobuf.portnums_pb2 import PortNum


def portnum_name(portnum):
    """Convert portnum integer to human-readable name."""
    try:
        return PortNum.Name(portnum)
    except ValueError:
        return f"UNKNOWN({portnum})"


def format_node_info(node, node_id=None):
    """Format node information for display."""
    # Check if this is a broadcast (0xffffffff)
    if node_id == 0xFFFFFFFF:
        return "Broadcast"

    if not node:
        return "Unknown"

    parts = []
    if node.long_name:
        parts.append(node.long_name)
    if node.short_name:
        parts.append(f"({node.short_name})")

    return " ".join(parts) if parts else f"Node {node.id}"


def packet_to_dict(packet, mesh_packet=None, decoded_payload=None):
    """Convert packet to dictionary for JSON output."""
    payload_size = len(packet.payload) if packet.payload else 0
    
    packet_dict = {
        "id": packet.id,
        "time": packet.import_time.isoformat() if packet.import_time else None,
        "port": {"number": packet.portnum, "name": portnum_name(packet.portnum)},
        "from": {
            "node_id_decimal": packet.from_node_id,
            "node_id_hex": hex(packet.from_node_id) if packet.from_node_id else None,
            "long_name": packet.from_node.long_name if packet.from_node else None,
            "short_name": packet.from_node.short_name if packet.from_node else None,
        },
        "to": {
            "node_id_decimal": packet.to_node_id,
            "node_id_hex": hex(packet.to_node_id) if packet.to_node_id else None,
            "long_name": packet.to_node.long_name if packet.to_node else None,
            "short_name": packet.to_node.short_name if packet.to_node else None,
            "is_broadcast": packet.to_node_id == 0xFFFFFFFF
            if packet.to_node_id
            else False,
        },
        "channel": packet.channel,
        "payload_size": payload_size,
        "decoded_payload": None,
    }

    if decoded_payload is not None:
        portnum = packet.portnum
        payload_data = {}

        if portnum == PortNum.TEXT_MESSAGE_APP:
            msg_size = (
                len(decoded_payload.encode("utf-8"))
                if isinstance(decoded_payload, str)
                else len(decoded_payload)
            )
            payload_data = {
                "type": "text_message",
                "size": msg_size,
                "message": decoded_payload,
            }

        elif portnum == PortNum.POSITION_APP:
            payload_data = {
                "type": "position",
                "latitude": decoded_payload.latitude_i / 1e7
                if decoded_payload.latitude_i
                else None,
                "longitude": decoded_payload.longitude_i / 1e7
                if decoded_payload.longitude_i
                else None,
                "altitude": decoded_payload.altitude
                if decoded_payload.altitude
                else None,
            }

        elif portnum == PortNum.NODEINFO_APP:
            payload_data = {
                "type": "node_info",
                "long_name": decoded_payload.long_name
                if decoded_payload.long_name
                else None,
                "short_name": decoded_payload.short_name
                if decoded_payload.short_name
                else None,
                "hw_model": decoded_payload.hw_model
                if decoded_payload.hw_model
                else None,
            }

        elif portnum == PortNum.TELEMETRY_APP:
            payload_data = {"type": "telemetry"}
            if decoded_payload.HasField("device_metrics"):
                dm = decoded_payload.device_metrics
                payload_data["device_metrics"] = {
                    "battery_level": dm.battery_level if dm.battery_level else None,
                    "voltage": dm.voltage if dm.voltage else None,
                    "channel_utilization": dm.channel_utilization
                    if dm.channel_utilization
                    else None,
                    "air_util_tx": dm.air_util_tx if dm.air_util_tx else None,
                }
            if decoded_payload.HasField("environment_metrics"):
                em = decoded_payload.environment_metrics
                payload_data["environment_metrics"] = {
                    "temperature": em.temperature if em.temperature else None,
                    "relative_humidity": em.relative_humidity
                    if em.relative_humidity
                    else None,
                    "barometric_pressure": em.barometric_pressure
                    if em.barometric_pressure
                    else None,
                }

        elif portnum == PortNum.TRACEROUTE_APP:
            payload_data = {
                "type": "traceroute",
                "route": [hex(node_id) for node_id in decoded_payload.route]
                if decoded_payload.route
                else [],
            }

        elif portnum == PortNum.NEIGHBORINFO_APP:
            neighbors = []
            if decoded_payload.neighbors:
                for neighbor in decoded_payload.neighbors:
                    neighbors.append(
                        {"node_id": hex(neighbor.node_id), "snr": neighbor.snr}
                    )
            payload_data = {"type": "neighbor_info", "neighbors": neighbors}

        elif portnum == PortNum.ROUTING_APP:
            payload_data = {
                "type": "routing",
                "error_reason": decoded_payload.error_reason
                if decoded_payload.HasField("error_reason")
                else None,
            }

        else:
            payload_data = {"type": "unknown", "port_name": portnum_name(portnum)}

        packet_dict["decoded_payload"] = payload_data

    return packet_dict


def format_json_with_color(json_str):
    """Format JSON string with syntax highlighting if pygments is available."""
    if PYGMENTS_AVAILABLE and sys.stdout.isatty():
        return highlight(json_str, JsonLexer(), TerminalFormatter())
    return json_str


def format_payload(mesh_packet, decoded_payload, portnum, payload_size=None):
    """Format decoded payload for display with color."""
    if decoded_payload is None:
        if payload_size:
            return f"{colorize('  [Payload could not be decoded]', Colors.RED)}\n  Payload Size: {payload_size} bytes"
        return colorize("  [Payload could not be decoded]", Colors.RED)

    lines = []
    portnum_str = portnum_name(portnum)

    if portnum == PortNum.TEXT_MESSAGE_APP:
        msg_size = (
            len(decoded_payload.encode("utf-8"))
            if isinstance(decoded_payload, str)
            else len(decoded_payload)
        )
        lines.append(colorize(f"  Text Message:", Colors.MAGENTA))
        lines.append(f"    Size: {msg_size} bytes")
        lines.append(f"    Message: {colorize(decoded_payload, Colors.WHITE, bold=True)}")

    elif portnum == PortNum.POSITION_APP:
        lat = decoded_payload.latitude_i / 1e7 if decoded_payload.latitude_i else None
        lon = decoded_payload.longitude_i / 1e7 if decoded_payload.longitude_i else None
        alt = decoded_payload.altitude if decoded_payload.altitude else None
        lines.append(colorize(f"  Position:", Colors.MAGENTA))
        if lat and lon:
            lines.append(f"    Lat/Lon: {colorize(f'{lat:.6f}, {lon:.6f}', Colors.BRIGHT_CYAN)}")
        if alt:
            lines.append(f"    Altitude: {colorize(f'{alt}m', Colors.BRIGHT_CYAN)}")

    elif portnum == PortNum.NODEINFO_APP:
        lines.append(colorize(f"  Node Info:", Colors.MAGENTA))
        if decoded_payload.long_name:
            lines.append(f"    Long Name: {colorize(decoded_payload.long_name, Colors.GREEN)}")
        if decoded_payload.short_name:
            lines.append(f"    Short Name: {colorize(decoded_payload.short_name, Colors.GREEN)}")
        if decoded_payload.hw_model:
            lines.append(f"    Hardware: {colorize(str(decoded_payload.hw_model), Colors.CYAN)}")

    elif portnum == PortNum.TELEMETRY_APP:
        lines.append(colorize(f"  Telemetry:", Colors.MAGENTA))
        if decoded_payload.HasField("device_metrics"):
            dm = decoded_payload.device_metrics
            if dm.battery_level:
                lines.append(f"    Battery: {colorize(f'{dm.battery_level}%', Colors.BRIGHT_GREEN)}")
            if dm.voltage:
                lines.append(f"    Voltage: {colorize(f'{dm.voltage}V', Colors.BRIGHT_GREEN)}")
            if dm.channel_utilization:
                lines.append(f"    Channel Utilization: {colorize(f'{dm.channel_utilization}%', Colors.YELLOW)}")
            if dm.air_util_tx:
                lines.append(f"    Air Utilization TX: {colorize(f'{dm.air_util_tx}%', Colors.YELLOW)}")
        if decoded_payload.HasField("environment_metrics"):
            em = decoded_payload.environment_metrics
            if em.temperature:
                lines.append(f"    Temperature: {colorize(f'{em.temperature}°C', Colors.BRIGHT_CYAN)}")
            if em.relative_humidity:
                lines.append(f"    Humidity: {colorize(f'{em.relative_humidity}%', Colors.BRIGHT_CYAN)}")
            if em.barometric_pressure:
                lines.append(f"    Pressure: {colorize(f'{em.barometric_pressure} hPa', Colors.BRIGHT_CYAN)}")

    elif portnum == PortNum.TRACEROUTE_APP:
        lines.append(colorize(f"  Traceroute:", Colors.MAGENTA))
        if decoded_payload.route:
            route_nodes = [colorize(hex(node_id), Colors.GREEN) for node_id in decoded_payload.route]
            lines.append(f"    Route: {' -> '.join(route_nodes)}")

    elif portnum == PortNum.NEIGHBORINFO_APP:
        lines.append(colorize(f"  Neighbor Info:", Colors.MAGENTA))
        if decoded_payload.neighbors:
            lines.append(f"    Neighbors: {len(decoded_payload.neighbors)}")
            for neighbor in decoded_payload.neighbors[:5]:  # Show first 5
                lines.append(f"      {colorize(hex(neighbor.node_id), Colors.GREEN)} (SNR: {colorize(str(neighbor.snr), Colors.CYAN)})")

    elif portnum == PortNum.ROUTING_APP:
        lines.append(colorize(f"  Routing:", Colors.MAGENTA))
        if decoded_payload.HasField("error_reason"):
            lines.append(f"    Error: {colorize(str(decoded_payload.error_reason), Colors.RED)}")

    else:
        if payload_size:
            lines.append(colorize(f"  {portnum_str}:", Colors.MAGENTA))
            lines.append(f"    Payload Size: {payload_size} bytes")
        else:
            lines.append(
                colorize(f"  {portnum_str}: [Raw payload size: {len(str(decoded_payload))} bytes]", Colors.GRAY)
            )

    return "\n".join(lines) if lines else colorize(f"  {portnum_str}", Colors.MAGENTA)


async def inspect_packets(
    database_path, count=100, portnum_filter=None, node_filter=None, exclude_node=None, channel_filter=None, json_output=False
):
    """
    Inspect the last N packets from the database.

    Args:
        database_path: Path to the SQLite database file
        count: Number of packets to retrieve
        portnum_filter: Optional portnum to filter by
        node_filter: Optional node_id to filter by (from or to)
        exclude_node: Optional node_id to exclude (from or to)
        channel_filter: Optional channel name to filter by
        json_output: Output in JSON format
    """
    # Create read-only database connection
    db_path = Path(database_path).resolve()
    if not db_path.exists():
        print(f"Error: Database file not found: {db_path}", file=sys.stderr)
        return 1

    connection_string = f"sqlite+aiosqlite:///{db_path}?mode=ro"

    engine = create_async_engine(
        connection_string, echo=False, connect_args={"uri": True}
    )
    async_session = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    try:
        async with async_session() as session:
            # Build query
            query = select(Packet)

            # Apply filters
            if portnum_filter is not None:
                query = query.where(Packet.portnum == portnum_filter)

            if node_filter is not None:
                query = query.where(
                    (Packet.from_node_id == node_filter)
                    | (Packet.to_node_id == node_filter)
                )
            
            if exclude_node is not None:
                query = query.where(
                    (Packet.from_node_id != exclude_node)
                    & (Packet.to_node_id != exclude_node)
                )
            
            if channel_filter is not None:
                query = query.where(Packet.channel == channel_filter)

            # Order by most recent and limit
            query = query.order_by(Packet.import_time.desc()).limit(count)

            # Execute query
            result = await session.execute(query)
            packets = result.scalars().all()

            if not packets:
                if json_output:
                    print(json.dumps({"packets": []}, indent=2))
                else:
                    print("No packets found matching the criteria.")
                return 0

            if json_output:
                # JSON output mode
                packets_list = []
                for packet in packets:
                    mesh_packet = None
                    decoded_payload = None

                    if packet.payload:
                        mesh_packet, decoded_payload = decode(packet)

                    packet_dict = packet_to_dict(packet, mesh_packet, decoded_payload)
                    packets_list.append(packet_dict)

                output = {"count": len(packets), "packets": packets_list}
                json_str = json.dumps(output, indent=2)
                print(format_json_with_color(json_str))
            else:
                # Text output mode
                print(f"\n{colorize('=' * 80, Colors.CYAN)}")
                print(colorize(f"Found {len(packets)} packet(s)", Colors.CYAN, bold=True))
                print(f"{colorize('=' * 80, Colors.CYAN)}\n")

                # Process and display each packet
                for i, packet in enumerate(packets, 1):
                    print(colorize(f"Packet #{i} (ID: {packet.id})", Colors.YELLOW, bold=True))
                    print(colorize('─' * 80, Colors.GRAY))

                    # Basic packet info
                    print(f"{colorize('Time:', Colors.BLUE)} {packet.import_time}")
                    port_name = portnum_name(packet.portnum)
                    print(f"{colorize('Port:', Colors.BLUE)} {colorize(port_name, Colors.MAGENTA)} ({packet.portnum})")

                    # Format From field with decimal and hex
                    from_node_name = format_node_info(packet.from_node, packet.from_node_id)
                    from_id_str = (
                        f"[{packet.from_node_id} / {hex(packet.from_node_id)}]"
                        if packet.from_node_id
                        else "[N/A]"
                    )
                    print(
                        f"{colorize('From:', Colors.BLUE)} {colorize(from_node_name, Colors.GREEN)} {colorize(from_id_str, Colors.GRAY)}"
                    )

                    # Format To field with decimal and hex
                    to_node_name = format_node_info(packet.to_node, packet.to_node_id)
                    to_id_str = (
                        f"[{packet.to_node_id} / {hex(packet.to_node_id)}]"
                        if packet.to_node_id
                        else "[N/A]"
                    )
                    to_color = Colors.RED if packet.to_node_id == 0xFFFFFFFF else Colors.GREEN
                    print(
                        f"{colorize('To:', Colors.BLUE)} {colorize(to_node_name, to_color)} {colorize(to_id_str, Colors.GRAY)}"
                    )

                    if packet.channel:
                        print(f"{colorize('Channel:', Colors.BLUE)} {colorize(packet.channel, Colors.CYAN, bold=True)}")

                    # Decode protobuf payload
                    if packet.payload:
                        payload_size = len(packet.payload)
                        mesh_packet, decoded_payload = decode(packet)
                        if mesh_packet:
                            print(f"\n{colorize('Decoded Payload:', Colors.YELLOW)}")
                            print(
                                format_payload(
                                    mesh_packet, decoded_payload, packet.portnum, payload_size
                                )
                            )
                        else:
                            print(f"\n{colorize('Decoded Payload:', Colors.YELLOW)}")
                            print(colorize("  [Payload could not be decoded]", Colors.RED))
                            print(f"  Payload Size: {payload_size} bytes")
                    else:
                        print(f"\n{colorize('[No payload]', Colors.GRAY)}")

                    print(f"\n{colorize('=' * 80, Colors.CYAN)}\n")

            return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1
    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(
        description="Inspect packets from Meshview SQLite database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Inspect last 100 packets
  %(prog)s packets.db
  
  # Inspect last 50 packets
  %(prog)s packets.db -n 50
  
  # Show only text messages
  %(prog)s packets.db --portnum 1
  
  # Show packets from/to specific node
  %(prog)s packets.db --node 0x123456
  
  # Show packets from specific channel
  %(prog)s packets.db --channel LongFast
  
Port Numbers:
  0  = UNKNOWN_APP
  1  = TEXT_MESSAGE_APP
  3  = POSITION_APP
  4  = NODEINFO_APP
  6  = ROUTING_APP
  67 = TELEMETRY_APP
  70 = TRACEROUTE_APP
  71 = NEIGHBORINFO_APP
        """,
    )

    parser.add_argument(
        "database",
        help="Path to the SQLite database file (default: packets.db)",
        nargs="?",
        default="packets.db",
    )

    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=100,
        help="Number of packets to retrieve (default: 100)",
    )

    parser.add_argument(
        "-p",
        "--portnum",
        type=int,
        help="Filter by port number (e.g., 1 for TEXT_MESSAGE_APP)",
    )

    parser.add_argument(
        "--node",
        type=lambda x: int(x, 0),  # Supports hex (0x123) or decimal
        help="Filter by node ID (from or to), supports hex (0x123) or decimal",
    )
    
    parser.add_argument(
        "--exclude-node",
        type=lambda x: int(x, 0),  # Supports hex (0x123) or decimal
        help="Exclude packets from/to node ID, supports hex (0x123) or decimal",
    )
    
    parser.add_argument(
        "-c",
        "--channel",
        type=str,
        help="Filter by channel name (e.g., 'LongFast', 'ShortFast')",
    )

    parser.add_argument("--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    # Run async function
    exit_code = asyncio.run(
        inspect_packets(
            args.database,
            count=args.count,
            portnum_filter=args.portnum,
            node_filter=args.node,
            exclude_node=args.exclude_node,
            channel_filter=args.channel,
            json_output=args.json,
        )
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
