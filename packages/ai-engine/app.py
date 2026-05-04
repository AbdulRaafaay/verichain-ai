"""
VeriChain AI — AI Risk Engine
Flask microservice providing anomaly-based risk scoring using Isolation Forest.
Security: HMAC-authenticated, internal-network-only, fail-closed design.
Maps to: FR-07, FR-08, FR-09 / NFR-07, NFR-08, NFR-09
"""

import os
import hmac
import hashlib
import logging
from flask import Flask, request, jsonify, abort
from risk_engine import RiskEngine
from model_integrity import verify_model_integrity

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load HMAC secret from environment — NEVER hardcode
AI_HMAC_SECRET = os.environ.get('AI_HMAC_SECRET')
if not AI_HMAC_SECRET:
    raise RuntimeError("FATAL: AI_HMAC_SECRET environment variable not set. HMAC is mandatory for Gateway authentication.")

# Verify model integrity against blockchain BEFORE starting (NFR-09)
# This will raise RuntimeError if hash mismatches — container will not start
logger.info("Verifying AI model integrity against blockchain record...")
try:
    verify_model_integrity()
    logger.info("Model integrity verified. Starting AI Risk Engine.")
except Exception as e:
    logger.critical(f"FATAL: Model integrity check failed: {e}. System Halted.")
    raise RuntimeError(f"FATAL: Model integrity failure: {e}")

# Load the risk engine (Isolation Forest model)
engine = RiskEngine()


def verify_hmac(request_body: bytes, provided_hmac: str) -> bool:
    """
    Verify HMAC-SHA256 of request body against the AI_HMAC_SECRET.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    expected = hmac.new(
        AI_HMAC_SECRET.encode(),
        request_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, provided_hmac)


@app.route('/health', methods=['GET'])
def health():
    """
    Health check + model validation metrics.
    Used by Docker Compose healthcheck and by the Trust Dashboard's status page.
    """
    return jsonify({
        'status':            'healthy',
        'model':             'loaded',
        'validation':        engine.validation_metrics,
        'featureMeans':      engine.feature_means.tolist(),
        'featureStds':       engine.feature_stds.tolist(),
    }), 200


@app.route('/score', methods=['POST'])
def score():
    """
    Score a session's risk level using the Isolation Forest model.
    
    Security checks:
    1. Verify HMAC of request body to authenticate the Gateway
    2. Validate required fields in payload
    3. Score using model and return 0-100 integer
    
    Input: JSON {sessionHash, resourceHash, accessVelocity, geoHash,
                 deviceIdHash, uniqueResources, downloadBytes}
    Output: JSON {riskScore: int(0-100)}
    
    Maps to: FR-07, NFR-07, NFR-08
    """
    # Step 1: Authenticate the Gateway via HMAC (NFR-07)
    provided_hmac = request.headers.get('X-Internal-Auth', '')
    if not provided_hmac:
        logger.warning("Request missing X-Internal-Auth header — rejecting")
        abort(403)

    request_body = request.get_data()
    if not verify_hmac(request_body, provided_hmac):
        logger.warning("HMAC verification failed — possible unauthorized access attempt")
        abort(403)

    # Step 2: Parse and validate payload
    data = request.get_json(silent=True)
    if not data:
        abort(400)

    required_fields = [
        'sessionHash', 'resourceHash', 'accessVelocity',
        'uniqueResources', 'downloadBytes'
    ]
    for field in required_fields:
        if field not in data:
            logger.warning(f"Missing required field: {field}")
            abort(400)

    # Step 3: Score the session (only numeric/hashed features — no PII)
    try:
        result = engine.score_with_reasons({
            'accessVelocity': float(data['accessVelocity']),
            'uniqueResources': int(data['uniqueResources']),
            'downloadBytes': int(data['downloadBytes']),
            'geoDistanceKm': float(data.get('geoDistanceKm', 0)),
            'timeSinceLast': float(data.get('timeSinceLast', 0)),
            'deviceIdMatch': int(data.get('deviceIdMatch', 1))
        })
        reason_summary = ', '.join([f"{r['feature']}(z={r['zScore']})" for r in result['reasons']]) or 'none'
        logger.info(
            f"Scored: hash={data['sessionHash'][:8]}... "
            f"score={result['riskScore']} reasons=[{reason_summary}]"
        )
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Scoring error: {str(e)} — returning fail-closed score 100")
        return jsonify({'riskScore': 100, 'reasons': [{'feature': 'engine_error', 'label': 'AI engine error'}], 'rawDecision': 0}), 200


if __name__ == '__main__':
    # Internal network only — bind to 0.0.0.0 within Docker but isolated by network policy
    app.run(host='0.0.0.0', port=5001, debug=False)  # nosec B104
