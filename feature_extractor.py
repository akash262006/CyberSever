"""
feature_extractor.py - Feature extraction for simulated network traffic.

Calculates:
1. packet_rate (pkts/sec)
2. avg_packet_size (bytes)
3. connection_density (ratio of unique ports probed / total window packets)
4. outbound_data_volume (outbound bytes transferred)
5. destination_port
"""

from typing import Dict, Any, List
import pandas as pd

FEATURE_COLUMNS = [
    "packet_rate",
    "avg_packet_size",
    "connection_density",
    "outbound_data_volume",
    "destination_port"
]


class FeatureExtractor:
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.packet_window: List[Dict[str, Any]] = []

    def reset_window(self) -> None:
        """Clear the sliding window history."""
        self.packet_window = []

    def add_packet(self, packet: Dict[str, Any]) -> None:
        """Add packet to sliding inspection window."""
        self.packet_window.append(packet)
        if len(self.packet_window) > self.window_size:
            self.packet_window.pop(0)

    def extract_features(self, packet: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract numerical features required for Isolation Forest ML model:
        1. packet_rate: instantaneous or windowed packet frequency
        2. avg_packet_size: rolling average size of packets
        3. connection_density: ratio of distinct destination ports probed in recent window
        4. outbound_data_volume: outbound payload bytes
        5. destination_port: target port number
        """
        self.add_packet(packet)
        
        # Calculate window-based metrics
        window_sizes = [p.get("packet_size", 0) for p in self.packet_window]
        window_ports = [p.get("destination_port", 80) for p in self.packet_window]
        
        avg_packet_size = float(sum(window_sizes) / len(window_sizes)) if window_sizes else float(packet.get("packet_size", 0))
        # Connection density: unique ports contacted / total window count (high during port scans)
        connection_density = float(len(set(window_ports)) / len(window_ports)) if window_ports else 0.1

        packet_rate = float(packet.get("packet_frequency", 1.0))
        outbound_volume = float(packet.get("outbound_bytes", packet.get("packet_size", 0)))
        dst_port = float(packet.get("destination_port", 80))

        return {
            "packet_rate": round(packet_rate, 2),
            "avg_packet_size": round(avg_packet_size, 2),
            "connection_density": round(connection_density, 3),
            "outbound_data_volume": round(outbound_volume, 2),
            "destination_port": dst_port,
        }

    @staticmethod
    def to_dataframe(features_list: List[Dict[str, float]]) -> pd.DataFrame:
        """Convert feature dicts into ordered DataFrame matching model columns."""
        df = pd.DataFrame(features_list)
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0.0
        return df[FEATURE_COLUMNS]
