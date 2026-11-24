"""
virtual_hardware.py - Complete software simulation of physical IoT hardware:
- ESP32 Microcontroller: Receives simulated HTTP POST commands with JSON payloads
- Virtual IoT Device: State (ON / OFF)
- Virtual Relay: Connected (ON) / Disconnected (OFF)
- Green Indicator LED: ON (Normal) / OFF (Quarantine)
- Red Indicator LED: OFF (Normal) / ON (Quarantine)
- Piezo Buzzer: OFF (Normal) / ON (Quarantine)

NOTE: This is a 100% software simulation, not an actual electrical disconnection.
"""

import time
import json
from typing import Dict, Any, List


class VirtualHardwareController:
    def __init__(self, device_id: str = "ESP32-IoT-Node-01", simulated_endpoint: str = "http://192.168.1.105/api/hardware/control"):
        self.device_id = device_id
        self.simulated_endpoint = simulated_endpoint
        
        # Hardware States
        self.iot_device = "ON"       # "ON" or "OFF"
        self.relay = "ON"            # "ON" (Connected) or "OFF" (Disconnected)
        self.green_led = "ON"        # "ON" or "OFF"
        self.red_led = "OFF"         # "ON" or "OFF"
        self.buzzer = "OFF"          # "ON" or "OFF"
        
        # State tracking and event logging
        self.system_state = "NORMAL" # "NORMAL" or "QUARANTINE"
        self.last_action_timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.last_http_post: Dict[str, Any] = {}
        self.event_log: List[Dict[str, Any]] = []

    def send_simulated_http_post(self, command: str, reason: str, anomaly_score: float = 0.0) -> Dict[str, Any]:
        """
        Simulate sending a JSON HTTP POST command over WiFi to the ESP32 controller.
        Endpoint: /api/hardware/control
        Payload: JSON with command, target device, timestamp, and security audit reason.
        """
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        payload = {
            "target_device": self.device_id,
            "command": command,
            "relay_action": "DISCONNECT" if command == "QUARANTINE" else "CONNECT",
            "reason": reason,
            "anomaly_score": anomaly_score,
            "timestamp": timestamp_str,
            "simulated": True
        }

        # Simulated HTTP Request & Response structure
        http_transaction = {
            "method": "POST",
            "url": self.simulated_endpoint,
            "headers": {"Content-Type": "application/json", "X-Simulation-Mode": "Software-Only"},
            "body": payload,
            "status_code": 200,
            "response": {
                "status": "SUCCESS",
                "message": f"Virtual ESP32 executed command '{command}'.",
                "timestamp": timestamp_str
            }
        }
        self.last_http_post = http_transaction
        return http_transaction

    def quarantine(self, reason: str = "ML Anomaly Detected", anomaly_score: float = -0.15) -> None:
        """
        Trigger QUARANTINE state:
        - IoT Device: OFF
        - Relay: OFF (Disconnected)
        - Green LED: OFF
        - Red LED: ON
        - Buzzer: ON
        """
        # 1. Send simulated JSON HTTP POST command
        http_record = self.send_simulated_http_post("QUARANTINE", reason, anomaly_score)

        # 2. Update virtual hardware states
        self.iot_device = "OFF"
        self.relay = "OFF"
        self.green_led = "OFF"
        self.red_led = "ON"
        self.buzzer = "ON"
        self.system_state = "QUARANTINE"
        self.last_action_timestamp = http_record["body"]["timestamp"]

        self.event_log.append({
            "timestamp": self.last_action_timestamp,
            "event": "QUARANTINE",
            "reason": reason,
            "score": anomaly_score,
            "device": self.device_id
        })

    def reset_normal(self) -> None:
        """
        Trigger RESET to NORMAL state:
        - IoT Device: ON
        - Relay: ON (Connected)
        - Green LED: ON
        - Red LED: OFF
        - Buzzer: OFF
        """
        http_record = self.send_simulated_http_post("RESET", "Operator manual reset / Network safe")

        self.iot_device = "ON"
        self.relay = "ON"
        self.green_led = "ON"
        self.red_led = "OFF"
        self.buzzer = "OFF"
        self.system_state = "NORMAL"
        self.last_action_timestamp = http_record["body"]["timestamp"]

        self.event_log.append({
            "timestamp": self.last_action_timestamp,
            "event": "RESET_NORMAL",
            "reason": "Operator reset",
            "score": 0.0,
            "device": self.device_id
        })

    def get_status(self) -> Dict[str, Any]:
        """Return full structured status of virtual hardware."""
        return {
            "device_id": self.device_id,
            "system_state": self.system_state,
            "iot_device": self.iot_device,
            "relay": self.relay,
            "relay_label": "CONNECTED" if self.relay == "ON" else "DISCONNECTED",
            "green_led": self.green_led,
            "red_led": self.red_led,
            "buzzer": self.buzzer,
            "last_action_timestamp": self.last_action_timestamp,
            "last_http_post": self.last_http_post,
            "disclaimer": "⚠️ Simulated Hardware Controller: All electrical actions are software-emulated."
        }


# Backwards compatibility alias
VirtualHardware = VirtualHardwareController
