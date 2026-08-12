"""
SentinelTrust Telemetry Collector
Simulates passive network telemetry collection from IoT devices.
In production, replace with Zeek/Kafka integration.
Aggregates per-device every 30 seconds.
"""

import asyncio
import random
import time
import math
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models.trust_engine import TrustEngine, TelemetryWindow
    from api.websocket_manager import ConnectionManager

logger = logging.getLogger(__name__)

COLLECTION_INTERVAL = 5   # seconds (use 30 in production)

# Realistic baseline telemetry per device type
DEVICE_BASELINES = {
    "camera": {
        "packet_rate": (40, 60),       # packets/sec range
        "byte_entropy": (2.5, 3.5),    # bits
        "dns_query_freq": (2, 8),      # queries/min
        "connection_duration": (5, 30),
        "unique_dest_ips": (1, 4),
        "inter_arrival_variance": (0.01, 0.1),
        "bandwidth_mbps": (1.0, 4.0),
        "port_entropy": (1.0, 2.0),
    },
    "sensor": {
        "packet_rate": (5, 15),
        "byte_entropy": (1.5, 2.5),
        "dns_query_freq": (0, 3),
        "connection_duration": (1, 10),
        "unique_dest_ips": (1, 2),
        "inter_arrival_variance": (0.5, 2.0),
        "bandwidth_mbps": (0.01, 0.1),
        "port_entropy": (0.5, 1.0),
    },
    "router": {
        "packet_rate": (150, 300),
        "byte_entropy": (4.0, 5.5),
        "dns_query_freq": (50, 150),
        "connection_duration": (0.5, 5),
        "unique_dest_ips": (20, 60),
        "inter_arrival_variance": (0.001, 0.01),
        "bandwidth_mbps": (10, 50),
        "port_entropy": (4.0, 5.0),
    },
    "thermostat": {
        "packet_rate": (2, 8),
        "byte_entropy": (1.0, 2.0),
        "dns_query_freq": (0, 2),
        "connection_duration": (2, 15),
        "unique_dest_ips": (1, 2),
        "inter_arrival_variance": (1.0, 5.0),
        "bandwidth_mbps": (0.001, 0.05),
        "port_entropy": (0.3, 0.8),
    },
    "gateway": {
        "packet_rate": (100, 200),
        "byte_entropy": (3.5, 5.0),
        "dns_query_freq": (20, 80),
        "connection_duration": (1, 20),
        "unique_dest_ips": (10, 30),
        "inter_arrival_variance": (0.01, 0.1),
        "bandwidth_mbps": (5, 30),
        "port_entropy": (3.0, 4.5),
    },
}


def _rand(lo, hi):
    return lo + random.random() * (hi - lo)


def simulate_telemetry(device_type: str) -> dict:
    """Generate realistic simulated telemetry for a device type."""
    baseline = DEVICE_BASELINES.get(device_type, DEVICE_BASELINES["sensor"])
    return {
        "timestamp": time.time(),
        "packet_rate": _rand(*baseline["packet_rate"]),
        "byte_entropy": _rand(*baseline["byte_entropy"]),
        "protocol_dist": {
            "tcp": round(_rand(0.5, 0.8), 2),
            "udp": round(_rand(0.1, 0.3), 2),
            "icmp": round(_rand(0.01, 0.1), 2),
        },
        "dns_query_freq": _rand(*baseline["dns_query_freq"]),
        "connection_duration": _rand(*baseline["connection_duration"]),
        "unique_dest_ips": int(_rand(*baseline["unique_dest_ips"])),
        "inter_arrival_variance": _rand(*baseline["inter_arrival_variance"]),
        "port_entropy": _rand(*baseline["port_entropy"]),
        "bandwidth_mbps": _rand(*baseline["bandwidth_mbps"]),
    }


class TelemetryCollector:
    def __init__(self):
        self._running = False

    async def start_collection(self, trust_engine, ws_manager):
        """Main collection loop: collect telemetry and update trust scores."""
        self._running = True
        logger.info("Telemetry collection started")

        # Import here to avoid circular imports
        from models.trust_engine import TelemetryWindow

        while self._running:
            updates = []
            for dev_id, device in trust_engine.devices.items():
                try:
                    raw = simulate_telemetry(device.device_type)
                    window = TelemetryWindow(
                        timestamp=raw["timestamp"],
                        packet_rate=raw["packet_rate"],
                        byte_entropy=raw["byte_entropy"],
                        protocol_dist=raw["protocol_dist"],
                        dns_query_freq=raw["dns_query_freq"],
                        connection_duration=raw["connection_duration"],
                        unique_dest_ips=raw["unique_dest_ips"],
                        inter_arrival_variance=raw["inter_arrival_variance"],
                        port_entropy=raw["port_entropy"],
                        bandwidth_mbps=raw["bandwidth_mbps"],
                    )
                    result = trust_engine.compute_trust_score(dev_id, window)
                    updates.append(result)
                except Exception as e:
                    logger.error(f"Error processing device {dev_id}: {e}")

            # Broadcast updates via WebSocket
            if updates:
                try:
                    await ws_manager.broadcast({
                        "type": "trust_update",
                        "timestamp": time.time(),
                        "devices": updates,
                        "summary": trust_engine.get_summary_stats(),
                        "alerts": trust_engine.get_recent_alerts(5),
                    })
                except Exception as e:
                    logger.error(f"Broadcast error: {e}")

            await asyncio.sleep(COLLECTION_INTERVAL)

    def stop(self):
        self._running = False
