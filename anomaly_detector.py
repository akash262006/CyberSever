"""
anomaly_detector.py - Scikit-learn Isolation Forest ML Anomaly Detector.

Key Responsibilities:
1. Unsupervised learning on normal IoT network traffic baseline.
2. Real-time ML inference (predict & decision_function).
3. Return anomaly scores.
4. Provide plain-language feature-based detection explanations for flagged anomalies.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, Tuple
from feature_extractor import FEATURE_COLUMNS, FeatureExtractor


class AnomalyDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_trained = False
        # Baseline threshold statistics recorded during normal training
        self.baseline_stats: Dict[str, Dict[str, float]] = {}

    def train_baseline(self, normal_samples: int = 1000) -> None:
        """
        Train Isolation Forest model on synthetic normal IoT telemetry baseline.
        Normal Profile:
        - packet_rate: 1.0 to 5.0 pkts/sec
        - avg_packet_size: 64 to 512 bytes
        - connection_density: low (repeats 1-2 standard ports like 80, 443, 1883, 5683, 53)
        - outbound_data_volume: 64 to 650 bytes
        - destination_port: normal IoT service ports
        """
        np.random.seed(self.random_state)
        
        rates = np.random.uniform(1.0, 5.0, size=normal_samples)
        sizes = np.random.uniform(64.0, 512.0, size=normal_samples)
        densities = np.random.uniform(0.1, 0.25, size=normal_samples)
        outbound = sizes + np.random.uniform(0.0, 150.0, size=normal_samples)
        ports = np.random.choice([80.0, 443.0, 1883.0, 5683.0, 53.0], size=normal_samples)

        train_df = pd.DataFrame({
            "packet_rate": rates,
            "avg_packet_size": sizes,
            "connection_density": densities,
            "outbound_data_volume": outbound,
            "destination_port": ports
        })[FEATURE_COLUMNS]

        # Record upper normal thresholds for human-readable explanations
        for col in FEATURE_COLUMNS:
            self.baseline_stats[col] = {
                "mean": float(train_df[col].mean()),
                "p99": float(np.percentile(train_df[col], 99)),
                "p01": float(np.percentile(train_df[col], 1)),
            }

        self.model.fit(train_df)
        self.is_trained = True

    def explain_anomaly(self, feats: Dict[str, float]) -> str:
        """
        Provides beginner-friendly detection explanation by comparing
        the incoming packet's anomalous features against normal baseline statistics.
        """
        reasons = []

        if feats["packet_rate"] > self.baseline_stats["packet_rate"]["p99"] * 2:
            reasons.append(f"Excessive packet rate ({feats['packet_rate']} pkts/s vs normal < {self.baseline_stats['packet_rate']['p99']:.1f})")

        if feats["outbound_data_volume"] > self.baseline_stats["outbound_data_volume"]["p99"] * 3:
            reasons.append(f"Massive outbound volume ({feats['outbound_data_volume']} B vs normal < {self.baseline_stats['outbound_data_volume']['p99']:.0f} B)")

        if feats["connection_density"] >= 0.5:
            reasons.append(f"High connection density ({feats['connection_density']:.2f}) indicating multi-port reconnaissance")

        if feats["destination_port"] not in [80.0, 443.0, 1883.0, 5683.0, 53.0]:
            if feats["connection_density"] > 0.35:
                reasons.append(f"Targeting non-standard port {int(feats['destination_port'])}")

        if not reasons:
            reasons.append("Multi-dimensional feature vector deviated from normal Isolation Forest cluster")

        return "; ".join(reasons)

    def predict(self, packet_features: Dict[str, float]) -> Tuple[bool, float, str, str]:
        """
        Performs genuine ML inference using Isolation Forest.
        Returns:
            is_anomaly (bool)
            anomaly_score (float): Isolation forest decision function value (negative = outlier)
            classification (str): "NORMAL" or "ANOMALOUS"
            explanation (str): Human-readable explanation of detected behavior
        """
        if not self.is_trained:
            self.train_baseline()

        df = FeatureExtractor.to_dataframe([packet_features])
        
        # Scikit-learn Isolation Forest decision function:
        # Negative scores represent anomalies, positive represents normal
        score = float(self.model.decision_function(df)[0])
        pred = int(self.model.predict(df)[0])  # 1: Inlier (normal), -1: Outlier (anomalous)

        is_anomaly = (pred == -1)
        classification = "ANOMALOUS" if is_anomaly else "NORMAL"
        
        if is_anomaly:
            explanation = self.explain_anomaly(packet_features)
        else:
            explanation = "Traffic profile conforms to normal IoT baseline telemetry."

        return is_anomaly, round(score, 4), classification, explanation
