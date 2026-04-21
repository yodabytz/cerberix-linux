"""
Cerberix AI — Traffic Anomaly Detector

Maintains a rolling baseline of network traffic metrics and flags
statistically significant deviations. Uses Isolation Forest for
multivariate anomaly detection once enough data is collected,
falls back to z-score analysis during warm-up.
"""

import time
import json
import os
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import numpy as np


@dataclass
class TrafficSnapshot:
    """A point-in-time traffic measurement."""
    timestamp: float
    connections_per_sec: float
    bytes_per_sec: float
    unique_src_ips: int
    unique_dst_ports: int
    dropped_packets: int
    dns_queries_per_sec: float


@dataclass
class AnomalyAlert:
    metric: str
    current_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    severity: str
    description: str
    snapshot: Optional[TrafficSnapshot] = None


class TrafficAnomalyDetector:
    """
    Two-phase anomaly detection:
    1. Warm-up (< 100 samples): z-score on individual metrics
    2. Mature (>= 100 samples): Isolation Forest on feature vectors

    Baselines are persisted to disk so restarts don't lose history.
    """

    def __init__(
        self,
        std_threshold: float = 3.0,
        baseline_window: int = 1000,
        data_dir: str = "/var/lib/cerberix/ai",
    ):
        self.std_threshold = std_threshold
        self.baseline_window = baseline_window
        self.data_dir = data_dir
        self._history: deque[TrafficSnapshot] = deque(maxlen=baseline_window)
        self._model = None
        self._model_trained = False
        self._min_samples_for_model = 100
        self._last_train_count = 0

        # Load persisted baseline
        self._load_baseline()

    def ingest(self, snapshot: TrafficSnapshot) -> list[AnomalyAlert]:
        """Ingest a traffic snapshot and check for anomalies."""
        self._history.append(snapshot)
        alerts = []

        if len(self._history) < 10:
            return alerts  # Not enough data

        # ── Z-Score analysis (always runs) ──────────────────
        metrics = {
            "connections_per_sec": [s.connections_per_sec for s in self._history],
            "bytes_per_sec": [s.bytes_per_sec for s in self._history],
            "unique_src_ips": [float(s.unique_src_ips) for s in self._history],
            "unique_dst_ports": [float(s.unique_dst_ports) for s in self._history],
            "dropped_packets": [float(s.dropped_packets) for s in self._history],
            "dns_queries_per_sec": [s.dns_queries_per_sec for s in self._history],
        }

        for metric_name, values in metrics.items():
            arr = np.array(values[:-1])  # Baseline excludes current
            current = values[-1]
            mean = float(np.mean(arr))
            std = float(np.std(arr))

            if std < 0.001:
                continue  # No variance — skip

            z = abs(current - mean) / std

            if z >= self.std_threshold:
                severity = "critical" if z > self.std_threshold * 2 else "high"
                direction = "spike" if current > mean else "drop"
                alerts.append(
                    AnomalyAlert(
                        metric=metric_name,
                        current_value=round(current, 2),
                        baseline_mean=round(mean, 2),
                        baseline_std=round(std, 2),
                        z_score=round(z, 2),
                        severity=severity,
                        description=(
                            f"Traffic anomaly: {metric_name} {direction} "
                            f"(current={current:.1f}, baseline={mean:.1f}±{std:.1f}, "
                            f"z={z:.1f})"
                        ),
                        snapshot=snapshot,
                    )
                )

        # ── Isolation Forest (when mature) ──────────────────
        if len(self._history) >= self._min_samples_for_model:
            model_alerts = self._isolation_forest_check(snapshot)
            alerts.extend(model_alerts)

        # Periodically save baseline
        if len(self._history) % 50 == 0:
            self._save_baseline()

        return alerts

    def _isolation_forest_check(
        self, snapshot: TrafficSnapshot
    ) -> list[AnomalyAlert]:
        """Run Isolation Forest on the feature vector."""
        alerts = []

        # Retrain if we have 50+ new samples since last train
        if (
            not self._model_trained
            or len(self._history) - self._last_train_count >= 50
        ):
            self._train_model()

        if self._model is None:
            return alerts

        features = self._snapshot_to_features(snapshot)
        prediction = self._model.predict(features.reshape(1, -1))
        score = self._model.decision_function(features.reshape(1, -1))[0]

        if prediction[0] == -1:  # Anomaly
            alerts.append(
                AnomalyAlert(
                    metric="multivariate",
                    current_value=round(float(score), 4),
                    baseline_mean=0.0,
                    baseline_std=0.0,
                    z_score=0.0,
                    severity="high" if score < -0.3 else "medium",
                    description=(
                        f"Isolation Forest anomaly detected "
                        f"(score={score:.4f})"
                    ),
                    snapshot=snapshot,
                )
            )

        return alerts

    def _train_model(self):
        """Train the Isolation Forest model on current baseline."""
        try:
            from sklearn.ensemble import IsolationForest

            X = np.array([
                self._snapshot_to_features(s) for s in self._history
            ])

            self._model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
                n_jobs=1,
            )
            self._model.fit(X)
            self._model_trained = True
            self._last_train_count = len(self._history)
        except Exception:
            self._model = None
            self._model_trained = False

    @staticmethod
    def _snapshot_to_features(s: TrafficSnapshot) -> np.ndarray:
        return np.array([
            s.connections_per_sec,
            s.bytes_per_sec,
            float(s.unique_src_ips),
            float(s.unique_dst_ports),
            float(s.dropped_packets),
            s.dns_queries_per_sec,
        ])

    def _save_baseline(self):
        """Persist baseline to disk."""
        os.makedirs(self.data_dir, exist_ok=True)
        path = os.path.join(self.data_dir, "traffic_baseline.json")
        data = [
            {
                "timestamp": s.timestamp,
                "connections_per_sec": s.connections_per_sec,
                "bytes_per_sec": s.bytes_per_sec,
                "unique_src_ips": s.unique_src_ips,
                "unique_dst_ports": s.unique_dst_ports,
                "dropped_packets": s.dropped_packets,
                "dns_queries_per_sec": s.dns_queries_per_sec,
            }
            for s in self._history
        ]
        try:
            with open(path, "w") as f:
                json.dump(data[-200:], f)  # Keep last 200 for restart
        except OSError:
            pass

    def _load_baseline(self):
        """Load persisted baseline from disk."""
        path = os.path.join(self.data_dir, "traffic_baseline.json")
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
            for entry in data:
                self._history.append(TrafficSnapshot(**entry))
        except (OSError, json.JSONDecodeError, TypeError):
            pass
