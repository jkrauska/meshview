from meshtastic.protobuf.mqtt_pb2 import MapReport
from meshtastic.protobuf.portnums_pb2 import PortNum
from meshtastic.protobuf.mesh_pb2 import (
    Position,
    NeighborInfo,
    User,
    RouteDiscovery,
    Routing,
    MeshPacket,
)
from meshtastic.protobuf.telemetry_pb2 import Telemetry
from google.protobuf.message import DecodeError


def text_message(payload):
    return payload.decode("utf-8")


DECODE_MAP = {
    PortNum.POSITION_APP: Position.FromString,
    PortNum.NEIGHBORINFO_APP: NeighborInfo.FromString,
    PortNum.NODEINFO_APP: User.FromString,
    PortNum.TELEMETRY_APP: Telemetry.FromString,
    PortNum.TRACEROUTE_APP: RouteDiscovery.FromString,
    PortNum.ROUTING_APP: Routing.FromString,
    PortNum.TEXT_MESSAGE_APP: text_message,
    PortNum.MAP_REPORT_APP: MapReport.FromString,
}


def decode_payload(portnum, payload):
    if portnum not in DECODE_MAP:
        return None
    try:
        payload = DECODE_MAP[portnum](payload)
    except (DecodeError, UnicodeDecodeError):
        print(payload, flush=True)
        return None
    return payload


def decode(packet):
    try:
        mesh_packet = MeshPacket.FromString(packet.payload)
    except DecodeError:
        return None, None

    payload = decode_payload(mesh_packet.decoded.portnum, mesh_packet.decoded.payload)
    if payload is None:
        return mesh_packet, None

    return mesh_packet, payload
