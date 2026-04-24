"""
VeriChain AI — Isolation Forest Risk Scoring Engine
Trains and serves anomaly detection for session behavioral analysis.
Maps to: FR-07, FR-09 / NFR-07, NFR-09
"""

import os
import hashlib
import logging
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')


class RiskEngine:
    """
    Isolation Forest-based anomaly detection engine.
    Features: [accessVelocity, uniqueResources, downloadBytes,
               geoDistanceKm, timeSinceLast, deviceIdMatch]
    Score: 0-100 (higher = more anomalous = higher risk)
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self._load_model()

    def _load_model(self):
        """Load pre-trained model and scaler from disk."""
        if not os.path.exists(MODEL_PATH):
            logger.warning("Model not found — training new model with synthetic baseline data")
            self._train_baseline_model()
        else:
            try:
                saved = joblib.load(MODEL_PATH)
                self.model = saved['model']
                self.scaler = saved['scaler']
                logger.info(f"Model loaded from {MODEL_PATH}")
            except Exception as e:
                logger.error(f"Failed to load model: {e} — re-training baseline")
                self._train_baseline_model()

    def _train_baseline_model(self):
        """
        Train Isolation Forest on synthetic baseline data.
        In production this is trained on real session telemetry.
        n_estimators=200 for stable scores; contamination=0.05 (~5% anomaly rate).
        """
        np.random.seed(42)
        # Synthetic normal behavior: low velocity, few resources, moderate data
        n_samples = 2000
        normal_data = np.column_stack([
            np.random.normal(5, 2, n_samples),     # accessVelocity: ~5 files/min
            np.random.randint(1, 10, n_samples),    # uniqueResources: 1-10
            np.random.normal(50000, 20000, n_samples),  # downloadBytes
            np.random.normal(0, 5, n_samples),      # geoDistanceKm: near base location
            np.random.normal(300, 100, n_samples),  # timeSinceLast: 5 min avg
            np.ones(n_samples),                     # deviceIdMatch: always 1 (normal)
        ])

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(normal_data)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
            max_samples='auto',
            n_jobs=-1
        )
        self.model.fit(X_scaled)

        # Save model + scaler together
        joblib.dump({'model': self.model, 'scaler': self.scaler}, MODEL_PATH)
        logger.info(f"Baseline model trained and saved to {MODEL_PATH}")

    def score(self, features: dict) -> int:
        """
        Score a session's features using the Isolation Forest.
        
        Returns: int 0-100 (0=normal, 100=maximum anomaly/risk)
        
        Security: if any step fails, returns 100 (fail-closed, NFR-07)
        """
        try:
            X = np.array([[
                features['accessVelocity'],
                features['uniqueResources'],
                features['downloadBytes'],
                features['geoDistanceKm'],
                features['timeSinceLast'],
                features['deviceIdMatch'],
            ]])
            X_scaled = self.scaler.transform(X)
            # decision_function: negative = anomalous, positive = normal
            # Typical range is [-0.15, 0.15] for normal samples in IF
            raw_score = self.model.decision_function(X_scaled)[0]
            
            # Map raw_score to 0-100 using a non-linear sigmoid-like approach
            # We want 0 for very normal (>0.1), ~50 for the threshold (~0), and 100 for very anomalous (<-0.1)
            # risk = 100 / (1 + exp(k * (score - offset)))
            # A simpler way:
            if raw_score > 0.12:
                risk_score = np.random.randint(0, 8) # Very safe
            elif raw_score > 0:
                # Map 0 to 0.12 -> 45 to 8
                risk_score = int(45 - (raw_score / 0.12) * 37)
            elif raw_score > -0.1:
                # Map -0.1 to 0 -> 90 to 45
                risk_score = int(90 - ((raw_score + 0.1) / 0.1) * 45)
            else:
                risk_score = np.random.randint(92, 101) # Very anomalous

            return int(np.clip(risk_score, 0, 100))
        except Exception as e:
            logger.error(f"Scoring exception: {e} — fail-closed, returning 100")
            return 100

    @staticmethod
    def compute_model_hash() -> str:
        """Compute SHA-256 hash of the model file for integrity verification."""
        if not os.path.exists(MODEL_PATH):
            return None
        with open(MODEL_PATH, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
