"""
traffic_generator.py - Simulates realistic network traffic for a virtual IoT device.
Scenarios:
1. Normal Traffic: Regular periodic sensor pings, standard packet sizes, low frequency.
2. DDoS-like Traffic: Sudden surge in packet frequency, small/medium packets to fixed server.
3. Port Scanning: Sequential or random connections across varied destination ports.
4. Data Exfiltration: Unusually large outbound byte transfers, periodic bursts.
"""

import time
import random
from typing import Dict, Any, Generator


class TrafficGenerator:
    def __init__(self, iot_ip: str = "192.168.1.105", server_ip: str = "192.168.1.1"):
        self.iot_ip = iot_ip
        self.server_ip = server_ip
        self.is_running = False
        self.current_scenario = "Normal Traffic"
        self._scan_port_cursor = 20

    def start(self, scenario: str = "Normal Traffic") -> None:
        """Start simulation under a specified scenario."""
        self.is_running = True
        self.current_scenario = scenario

    def stop(self) -> None:
        """Stop simulation."""
        self.is_running = False

    def set_scenario(self, scenario: str) -> None:
        """Change traffic scenario dynamically."""
        self.current_scenario = scenario

    def generate_packet(self) -> Dict[str, Any]:
        """
        Generates a single synthetic packet record based on current scenario.
        Returns dictionary with features:
        - timestamp: float epoch time
        - source_ip: str
        - destination_ip: str
        - protocol: str (TCP, UDP, ICMP)
        - destination_port: int
        - packet_size: int (bytes)
        - packet_frequency: float (packets per second estimate)
        - outbound_bytes: int (bytes sent out by IoT device)
        - label: str (ground-truth scenario for validation)
        """
        timestamp = time.time()

        if self.current_scenario == "Normal Traffic":
            # Normal IoT telemetry: MQTT (1883), HTTP/S (80/443), CoAP (5683), or DNS (53)
            protocol = random.choices(["TCP", "UDP"], weights=[0.8, 0.2])[0]
            dst_port = random.choice([80, 443, 1883, 5683, 53])
            packet_size = random.randint(64, 512)
            packet_frequency = round(random.uniform(1.0, 5.0), 2)  # 1-5 pkts/sec
            outbound_bytes = packet_size + random.randint(0, 150)
            label = "Normal"

        elif self.current_scenario == "DDoS-like Traffic":
            # Massive spike in frequency, targeted at single server
            protocol = random.choice(["TCP", "UDP"])
            dst_port = random.choice([80, 443, 8080])
            packet_size = random.randint(64, 256)
            packet_frequency = round(random.uniform(80.0, 250.0), 2)  # High frequency burst
            outbound_bytes = packet_size
            label = "DDoS"

        elif self.current_scenario == "Port Scanning":
            # Scanning various ports sequentially or randomly across target range
            protocol = "TCP"
            self._scan_port_cursor = (self._scan_port_cursor + random.randint(1, 5)) % 65535
            dst_port = self._scan_port_cursor if self._scan_port_cursor > 0 else 22
            packet_size = random.randint(40, 80)  # Small probe packets (SYN-like)
            packet_frequency = round(random.uniform(15.0, 45.0), 2)
            outbound_bytes = packet_size
            label = "Port Scan"

        elif self.current_scenario == "Data Exfiltration":
            # Very large outbound payloads (file transfer/leakage)
            protocol = "TCP"
            dst_port = random.choice([443, 8080, 9001, 21])
            packet_size = random.randint(1200, 4096)
            packet_frequency = round(random.uniform(5.0, 20.0), 2)
            outbound_bytes = random.randint(15000, 85000)  # Massive outbound byte volume
            label = "Exfiltration"

        else:
            # Fallback
            protocol = "TCP"
            dst_port = 80
            packet_size = 128
            packet_frequency = 2.0
            outbound_bytes = 128
            label = "Normal"

        return {
            "timestamp": timestamp,
            "source_ip": self.iot_ip,
            "destination_ip": self.server_ip,
            "protocol": protocol,
            "destination_port": dst_port,
            "packet_size": packet_size,
            "packet_frequency": packet_frequency,
            "outbound_bytes": outbound_bytes,
            "scenario": self.current_scenario,
            "ground_truth": label,
        }

    def stream(self, count: int = 10, delay: float = 0.1) -> Generator[Dict[str, Any], None, None]:
        """Yields packet stream while generator is running."""
        for _ in range(count):
            if not self.is_running:
                break
            yield self.generate_packet()
            if delay > 0:
                time.sleep(delay)


if __name__ == "__main__":
    print("Testing TrafficGenerator with all 4 scenarios...")
    gen = TrafficGenerator()
    scenarios = ["Normal Traffic", "DDoS-like Traffic", "Port Scanning", "Data Exfiltration"]
    
    for sc in scenarios:
        gen.start(sc)
        print(f"\n--- Scenario: {sc} ---")
        for pkt in gen.stream(count=3, delay=0.01):
            print(f"[{pkt['protocol']}] Port:{pkt['destination_port']} | Size:{pkt['packet_size']}B | Freq:{pkt['packet_frequency']}/s | Outbound:{pkt['outbound_bytes']}B | Label:{pkt['ground_truth']}")
        gen.stop()
    print("\nTrafficGenerator test completed successfully!")
