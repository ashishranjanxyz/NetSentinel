"""
NetSentinel - AI/ML Engine
- Isolation Forest for anomaly detection (unsupervised)
- Risk classifier using synthetic training data
- Explainable output for each prediction
"""

import numpy as np
import json
import os
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import warnings

warnings.filterwarnings("ignore")

# ──────────────────────────────────────────────
# Synthetic Training Data
# Features: [num_open_ports, has_critical, has_db, has_remote, has_legacy, risk_score]
# ──────────────────────────────────────────────

TRAINING_DATA = [
    # Low risk hosts
    [1, 0, 0, 0, 0, 1],   # Only HTTP
    [2, 0, 0, 0, 0, 2],   # HTTP + HTTPS
    [1, 0, 0, 0, 0, 1],
    [2, 0, 0, 0, 0, 3],
    [3, 0, 0, 0, 0, 3],   # Web + DNS
    [1, 0, 0, 0, 0, 2],
    [2, 0, 0, 0, 0, 2],

    # Medium risk hosts
    [3, 0, 0, 1, 0, 5],   # SSH + web
    [4, 0, 0, 1, 0, 6],   # SSH + SMTP + web
    [3, 0, 0, 1, 0, 5],
    [5, 0, 0, 1, 0, 7],
    [4, 0, 1, 0, 0, 7],   # DB exposed
    [3, 0, 1, 0, 0, 6],
    [2, 0, 0, 1, 0, 5],

    # High risk hosts
    [6, 1, 0, 1, 1, 14],  # Critical + legacy
    [5, 1, 1, 1, 0, 15],  # Critical + DB
    [7, 1, 1, 1, 1, 18],  # Everything bad
    [4, 1, 0, 1, 1, 12],
    [5, 0, 1, 1, 1, 13],
    [6, 1, 1, 0, 1, 16],
    [8, 1, 1, 1, 1, 20],  # Worst case
]

TRAINING_LABELS = [
    "LOW", "LOW", "LOW", "LOW", "LOW", "LOW", "LOW",
    "MEDIUM", "MEDIUM", "MEDIUM", "MEDIUM", "MEDIUM", "MEDIUM", "MEDIUM",
    "HIGH", "HIGH", "HIGH", "HIGH", "HIGH", "HIGH", "HIGH"
]

# Anomaly reference (normal traffic baseline)
NORMAL_BASELINE = [
    [1, 0, 0, 0, 0, 1],
    [2, 0, 0, 0, 0, 2],
    [2, 0, 0, 0, 0, 3],
    [3, 0, 0, 0, 0, 3],
    [1, 0, 0, 0, 0, 2],
    [2, 0, 0, 1, 0, 4],
    [3, 0, 0, 1, 0, 5],
]

FEATURE_NAMES = [
    "Open Ports Count",
    "Has Critical Ports",
    "Has DB Ports Exposed",
    "Has Remote Access",
    "Has Legacy Services",
    "Total Risk Score"
]


class NetSentinelAI:
    def __init__(self):
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self._train()

    def _train(self):
        """Train both models on synthetic data."""
        X = np.array(TRAINING_DATA)
        y = TRAINING_LABELS
        X_normal = np.array(NORMAL_BASELINE)

        # Risk Classifier (Random Forest)
        self.classifier = Pipeline([
            ("scaler", StandardScaler()),
            ("rf", RandomForestClassifier(
                n_estimators=100,
                max_depth=5,
                random_state=42,
                class_weight="balanced"
            ))
        ])
        self.classifier.fit(X, y)

        # Anomaly Detector (Isolation Forest)
        # Trained on "normal" hosts — flags unusual port combinations
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=42
        )
        self.anomaly_detector.fit(X_normal)

    def analyze(self, feature_vector: list, port_data: list) -> dict:
        """
        Full AI analysis of a scanned host.
        Returns risk level, anomaly flag, confidence, and explanation.
        """
        if not any(feature_vector):
            return {
                "risk_level": "NONE",
                "confidence": 100,
                "is_anomaly": False,
                "anomaly_score": 0,
                "explanation": ["No open ports detected. Host may be firewalled."],
                "top_threats": []
            }

        X = np.array([feature_vector])

        # Risk classification
        risk_level = self.classifier.predict(X)[0]
        proba = self.classifier.predict_proba(X)[0]
        classes = self.classifier.classes_
        confidence = round(float(max(proba)) * 100, 1)

        # Anomaly detection
        anomaly_pred = self.anomaly_detector.predict(X)[0]
        anomaly_score = self.anomaly_detector.score_samples(X)[0]
        is_anomaly = anomaly_pred == -1

        # Generate human-readable explanation
        explanation = self._explain(feature_vector, risk_level, is_anomaly)

        # Top threats from port data
        top_threats = self._get_top_threats(port_data)

        return {
            "risk_level": risk_level,
            "confidence": confidence,
            "is_anomaly": is_anomaly,
            "anomaly_score": round(float(anomaly_score), 4),
            "explanation": explanation,
            "top_threats": top_threats,
            "feature_breakdown": dict(zip(FEATURE_NAMES, feature_vector))
        }

    def _explain(self, features: list, risk: str, is_anomaly: bool) -> list:
        """Generate plain English explanation of AI decision."""
        explanations = []

        num_ports, has_critical, has_db, has_remote, has_legacy, risk_score = features

        if num_ports == 0:
            return ["No open ports found."]

        explanations.append(f"Found {num_ports} open port(s) with a total risk score of {risk_score}.")

        if has_critical:
            explanations.append(
                "⚠️  Critical services detected (e.g., RDP, SMB, VNC, Redis, MongoDB). "
                "These are common ransomware and exploitation vectors."
            )
        if has_db:
            explanations.append(
                "🗄️  Database ports are publicly exposed. This is a major security risk — "
                "databases should never be directly internet-accessible."
            )
        if has_remote:
            explanations.append(
                "🖥️  Remote access services found (SSH/RDP/Telnet/VNC). "
                "Ensure strong auth, MFA, and VPN gating are in place."
            )
        if has_legacy:
            explanations.append(
                "⚡ Legacy/insecure protocols detected (FTP, Telnet, POP3, NetBIOS). "
                "These transmit data in plaintext and should be disabled."
            )
        if is_anomaly:
            explanations.append(
                "🔴 ANOMALY DETECTED: This port combination is statistically unusual "
                "compared to normal server profiles. Manual investigation recommended."
            )

        risk_context = {
            "LOW": "Overall profile appears relatively safe for a public-facing server.",
            "MEDIUM": "Moderate attack surface. Harden exposed services and review firewall rules.",
            "HIGH": "High risk profile. Immediate remediation required on critical findings."
        }
        explanations.append(risk_context.get(risk, ""))

        return [e for e in explanations if e]

    def _get_top_threats(self, port_data: list) -> list:
        """Return top threat entries sorted by severity."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        sorted_ports = sorted(
            port_data,
            key=lambda p: severity_order.get(p.get("known_risk", "UNKNOWN"), 4)
        )
        return sorted_ports[:5]  # Top 5 threats

    def get_model_info(self) -> dict:
        """Return metadata about the trained models."""
        return {
            "classifier": "Random Forest (100 estimators)",
            "anomaly_detector": "Isolation Forest (contamination=0.15)",
            "training_samples": len(TRAINING_DATA),
            "features": FEATURE_NAMES,
            "classes": list(self.classifier.classes_)
        }
