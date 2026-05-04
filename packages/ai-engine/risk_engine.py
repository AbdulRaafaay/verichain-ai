"""
VeriChain AI — Isolation Forest Risk Scoring Engine
Trains and serves anomaly detection for session behavioural analysis.
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

FEATURE_LABELS = [
    'accessVelocity',
    'uniqueResources',
    'downloadBytes',
    'geoDistanceKm',
    'timeSinceLast',
    'deviceIdMatch',
]

# Per-feature explanation metadata.
# `direction='high'` = anomalous when value is high; `direction='low'` = anomalous when low.
FEATURE_EXPLAIN = {
    'accessVelocity':  {'direction': 'high', 'label': 'Access velocity',         'unit': 'req/min'},
    'uniqueResources': {'direction': 'high', 'label': 'Unique resources',        'unit': 'files'},
    'downloadBytes':   {'direction': 'high', 'label': 'Download volume',         'unit': 'bytes'},
    'geoDistanceKm':   {'direction': 'high', 'label': 'Geographic distance',     'unit': 'km'},
    'timeSinceLast':   {'direction': 'low',  'label': 'Time since last request', 'unit': 's'},
    'deviceIdMatch':   {'direction': 'low',  'label': 'Device fingerprint',      'unit': ''},
}


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
        self.df_min = -0.30
        self.df_max = 0.20
        # Training distribution stats — used for per-feature explainability
        self.feature_means = np.zeros(6)
        self.feature_stds = np.ones(6)
        # Validation metrics from the held-out attack-pattern set
        self.validation_metrics = {}
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
                self.df_min = float(saved.get('df_min', -0.30))
                self.df_max = float(saved.get('df_max',  0.20))
                if 'feature_means' in saved and 'feature_stds' in saved:
                    self.feature_means = np.array(saved['feature_means'])
                    self.feature_stds = np.array(saved['feature_stds'])
                else:
                    # Older model file — re-derive stats so explainability still works.
                    self.feature_means = np.array([5.0, 5.0, 50000.0, 0.0, 300.0, 1.0])
                    self.feature_stds = np.array([2.0, 3.0, 20000.0, 5.0, 100.0, 1.0])
                self.validation_metrics = saved.get('validation_metrics', {})
                logger.info(f"Model loaded from {MODEL_PATH} (df_min={self.df_min:.4f}, df_max={self.df_max:.4f})")
                if self.validation_metrics:
                    logger.info(
                        f"Validation: recall@50={self.validation_metrics.get('recall_at_50', '?')}  "
                        f"recall@75={self.validation_metrics.get('recall_at_75', '?')}  "
                        f"FP@50={self.validation_metrics.get('false_positive_50', '?')}"
                    )
            except Exception as e:
                logger.error(f"Failed to load model: {e} — re-training baseline")
                self._train_baseline_model()

    def _generate_attack_samples(self, n: int = 250):
        """
        Synthesise five realistic exfiltration / abuse patterns for validation.
        Each pattern has *correlated* feature spikes — closer to real attacker behaviour
        than independent-feature noise, and lets us measure recall before deployment.

        Returns: (X, labels) — X has shape (n, 6), labels are pattern names.
        """
        per_pattern = n // 5
        rng = np.random.default_rng(seed=99)

        # 1. Mass enumeration — attacker scripts crawl every file rapidly
        mass_enum = np.column_stack([
            rng.normal(50, 10, per_pattern),                  # velocity high
            rng.normal(35, 8, per_pattern),                   # resources high
            rng.normal(2_000_000, 500_000, per_pattern),      # bytes elevated
            rng.normal(15, 10, per_pattern),                  # geo near base
            rng.normal(2, 1, per_pattern),                    # rapid (low time)
            rng.choice([0, 1], per_pattern, p=[0.7, 0.3]),    # often new device
        ])
        # 2. Bulk download — single big exfil
        bulk_dl = np.column_stack([
            rng.normal(8, 3, per_pattern),                    # velocity normal-ish
            rng.normal(3, 2, per_pattern),                    # few resources
            rng.normal(50_000_000, 10_000_000, per_pattern),  # huge bytes
            rng.normal(10, 50, per_pattern),                  # geo normal
            rng.normal(120, 60, per_pattern),                 # time normal
            rng.choice([0, 1], per_pattern, p=[0.3, 0.7]),
        ])
        # 3. Geographic anomaly — login from far away
        geo_anom = np.column_stack([
            rng.normal(6, 3, per_pattern),
            rng.normal(5, 3, per_pattern),
            rng.normal(800_000, 400_000, per_pattern),
            rng.normal(2_500, 800, per_pattern),              # geo VERY far
            rng.normal(300, 100, per_pattern),
            rng.choice([0, 1], per_pattern, p=[0.6, 0.4]),
        ])
        # 4. Rapid-fire — credential stuffing / brute-force pattern
        rapid = np.column_stack([
            rng.normal(80, 15, per_pattern),                  # very high velocity
            rng.normal(8, 4, per_pattern),                    # few resources (same target)
            rng.normal(100_000, 50_000, per_pattern),         # small bytes per req
            rng.normal(20, 30, per_pattern),
            rng.normal(1, 0.5, per_pattern),                  # ≈1s between hits
            rng.choice([0, 1], per_pattern, p=[0.5, 0.5]),
        ])
        # 5. Stolen device — unknown device + medium activity
        stolen = np.column_stack([
            rng.normal(15, 5, per_pattern),
            rng.normal(12, 4, per_pattern),
            rng.normal(5_000_000, 2_000_000, per_pattern),
            rng.normal(400, 200, per_pattern),
            rng.normal(60, 30, per_pattern),
            np.zeros(per_pattern),                            # device mismatch
        ])

        X = np.vstack([mass_enum, bulk_dl, geo_anom, rapid, stolen])
        # Physical clipping (no negatives where impossible)
        X[:, 0] = np.clip(X[:, 0], 0, None)
        X[:, 1] = np.clip(X[:, 1], 1, None).round()
        X[:, 2] = np.clip(X[:, 2], 0, None)
        X[:, 4] = np.clip(X[:, 4], 1, None)
        labels = (['mass_enumeration'] * per_pattern + ['bulk_download'] * per_pattern +
                  ['geo_anomaly'] * per_pattern + ['rapid_fire'] * per_pattern +
                  ['stolen_device'] * per_pattern)
        return X, labels

    def _train_baseline_model(self):
        """
        Train Isolation Forest on synthetic baseline data, then validate the resulting
        model against a held-out attack-pattern set so the recall metric is recorded
        with the model rather than assumed.

        Distribution widths match realistic user behaviour:
        - velocity 5±5 req/min  → 15 = mild outlier (z≈2), 40 = strong (z≈7)
        - resources 5±3 files   → 10 = mild, 25 = strong
        - downloadBytes 500K±3M → 5MB = mild, 30MB = strong
        - geoDistanceKm 10±50   → 100km = mild, 300km = strong (covers commute/travel)
        - timeSinceLast 300±100 → low = anomalous (rapid-fire)
        - deviceIdMatch — 95% match, 5% mismatch (no longer zero-variance, so the
          feature actually contributes to the score)
        """
        np.random.seed(42)
        n_samples = 2000
        normal_data = np.column_stack([
            np.random.normal(5, 5, n_samples),                                # accessVelocity req/min
            np.random.normal(5, 3, n_samples),                                # uniqueResources
            np.random.normal(500_000, 3_000_000, n_samples),                  # downloadBytes (~500 KB)
            np.random.normal(10, 50, n_samples),                              # geoDistanceKm
            np.random.normal(300, 100, n_samples),                            # timeSinceLast
            np.random.choice([0, 1], n_samples, p=[0.05, 0.95]).astype(float),  # deviceIdMatch (5% mismatch)
        ])
        normal_data[:, 0] = np.clip(normal_data[:, 0], 0, None)
        normal_data[:, 1] = np.clip(normal_data[:, 1], 1, None).round()
        normal_data[:, 2] = np.clip(normal_data[:, 2], 0, None)
        normal_data[:, 4] = np.clip(normal_data[:, 4], 1, None)

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

        df_values = self.model.decision_function(X_scaled)
        self.df_min = float(df_values.min())
        self.df_max = float(df_values.max())
        # Per-feature stats for the explainability layer
        self.feature_means = normal_data.mean(axis=0)
        self.feature_stds = normal_data.std(axis=0)
        # Avoid div-by-zero on zero-variance features (deviceIdMatch in training)
        self.feature_stds[self.feature_stds < 1e-6] = 1.0

        logger.info(f"Calibrated range: df_min={self.df_min:.4f}, df_max={self.df_max:.4f}")
        logger.info(f"Feature means: {self.feature_means.round(2).tolist()}")

        # ── Validation pass — measure recall against held-out attack patterns ──
        attack_X, attack_labels = self._generate_attack_samples(n=250)
        attack_scaled = self.scaler.transform(attack_X)
        attack_raw = self.model.decision_function(attack_scaled)
        df_range = max(self.df_max - self.df_min, 1e-6)
        attack_scores = np.clip((1.0 - (attack_raw - self.df_min) / df_range) * 100.0, 0, 100)

        # False-positive rate on the training normals
        normal_raw = self.model.decision_function(X_scaled)
        normal_scores = np.clip((1.0 - (normal_raw - self.df_min) / df_range) * 100.0, 0, 100)

        recall_at_50 = float((attack_scores >= 50).mean())
        recall_at_75 = float((attack_scores >  75).mean())
        fp_rate_50  = float((normal_scores >= 50).mean())
        fp_rate_75  = float((normal_scores >  75).mean())

        # Per-pattern recall — useful for the report
        per_pattern_recall = {}
        for pattern in sorted(set(attack_labels)):
            mask = np.array([lbl == pattern for lbl in attack_labels])
            per_pattern_recall[pattern] = float((attack_scores[mask] >= 50).mean())

        validation_metrics = {
            'recall_at_50':       round(recall_at_50, 3),
            'recall_at_75':       round(recall_at_75, 3),
            'false_positive_50':  round(fp_rate_50, 3),
            'false_positive_75':  round(fp_rate_75, 3),
            'per_pattern_recall': {k: round(v, 3) for k, v in per_pattern_recall.items()},
            'attack_count':       len(attack_labels),
            'normal_count':       int(X_scaled.shape[0]),
        }
        self.validation_metrics = validation_metrics
        logger.info(
            f"Validation: recall(STEP_UP+REVOKE)@50={recall_at_50:.1%}  "
            f"recall(REVOKE)@75={recall_at_75:.1%}  "
            f"FP@50={fp_rate_50:.1%}  FP@75={fp_rate_75:.1%}"
        )
        for pat, rec in per_pattern_recall.items():
            logger.info(f"  · {pat:18s} → recall@50 = {rec:.1%}")

        joblib.dump({
            'model':              self.model,
            'scaler':             self.scaler,
            'df_min':             self.df_min,
            'df_max':             self.df_max,
            'feature_means':      self.feature_means.tolist(),
            'feature_stds':       self.feature_stds.tolist(),
            'validation_metrics': validation_metrics,
        }, MODEL_PATH)
        logger.info(f"Baseline model trained and saved to {MODEL_PATH}")

    def score(self, features: dict) -> float:
        """Backwards-compatible — returns just the float score."""
        return self.score_with_reasons(features)['riskScore']

    def score_with_reasons(self, features: dict) -> dict:
        """
        Score a session AND return the most-anomalous features that drove the score.

        Returns:
            {
                'riskScore':   float 0–100,
                'reasons':     [ { feature, label, value, expected, zScore, deviation, direction, unit }, … ],
                'rawDecision': float (raw IsolationForest output),
            }

        The reasons list is sorted most-anomalous-first; only features with |z| > 1.5
        are included so PERMIT decisions return short or empty lists.
        Fail-closed: any error returns 100 with a generic 'engine_error' reason (NFR-07).
        """
        try:
            raw_values = np.array([
                float(features['accessVelocity']),
                float(features['uniqueResources']),
                float(features['downloadBytes']),
                float(features['geoDistanceKm']),
                float(features['timeSinceLast']),
                float(features['deviceIdMatch']),
            ])
            X = raw_values.reshape(1, -1)
            X_scaled = self.scaler.transform(X)
            raw_val = float(self.model.decision_function(X_scaled)[0])

            df_range = max(self.df_max - self.df_min, 1e-6)
            risk_score = float(np.clip(
                (1.0 - (raw_val - self.df_min) / df_range) * 100.0,
                0.0, 100.0
            ))
            risk_score = round(risk_score, 2)

            # Per-feature z-scores → contributors panel.
            # Include EVERY feature with |z| > 1.5, but mark whether it's in the
            # anomaly direction (concerning) or just unusual-but-safe (informational).
            # This way the dashboard never says "all normal" while the score is 41.
            z_scores = (raw_values - self.feature_means) / self.feature_stds
            reasons = []
            for i, label in enumerate(FEATURE_LABELS):
                z = float(z_scores[i])
                meta = FEATURE_EXPLAIN[label]
                deviation = z if meta['direction'] == 'high' else -z

                if abs(z) > 1.5:
                    reasons.append({
                        'feature':    label,
                        'label':      meta['label'],
                        'value':      float(raw_values[i]),
                        'expected':   float(self.feature_means[i]),
                        'zScore':     round(z, 2),
                        'deviation':  round(deviation, 2),
                        'direction':  meta['direction'],
                        'concerning': deviation > 1.5,   # True = anomaly direction
                        'unit':       meta['unit'],
                    })

            reasons.sort(key=lambda r: -abs(r['zScore']))

            # ── Hybrid scoring — z-score floor for single-feature extremes ──
            # IF saturates on extreme single-axis outliers (geo=500km gets the
            # same isolation depth as geo=300km). Apply post-hoc floors so a
            # 9σ deviation in the anomaly direction never slips through as PERMIT.
            max_concerning_dev = max(
                (r['deviation'] for r in reasons if r['concerning']),
                default=0.0
            )
            score_floor = 0.0
            floor_reason = None
            if max_concerning_dev >= 7.0:
                score_floor = 76.0   # force at least REVOKE
                floor_reason = 'extreme_single_feature_outlier'
            elif max_concerning_dev >= 4.0:
                score_floor = 51.0   # force at least STEP_UP
                floor_reason = 'strong_single_feature_outlier'

            if score_floor > risk_score:
                logger.info(
                    f"Score floor applied: IF score {risk_score} → {score_floor} "
                    f"(reason={floor_reason}, max deviation={max_concerning_dev:.2f})"
                )
                risk_score = score_floor

            return {
                'riskScore':   risk_score,
                'reasons':     reasons[:4],  # top 4 contributors (concerning first by abs(z))
                'rawDecision': round(raw_val, 4),
                'scoreFloor':  floor_reason,  # null when IF score was already sufficient
            }
        except Exception as e:
            logger.error(f"Scoring exception: {e} — fail-closed, returning 100")
            return {
                'riskScore':   100.0,
                'reasons': [{
                    'feature': 'engine_error', 'label': 'AI engine error',
                    'value': 0, 'expected': 0, 'zScore': 0, 'deviation': 0,
                    'direction': 'high', 'unit': '',
                }],
                'rawDecision': 0.0,
            }

    @staticmethod
    def compute_model_hash() -> str:
        """Compute SHA-256 hash of the model file for integrity verification."""
        if not os.path.exists(MODEL_PATH):
            return None
        with open(MODEL_PATH, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
