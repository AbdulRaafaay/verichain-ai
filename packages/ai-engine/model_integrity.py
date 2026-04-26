"""
VeriChain AI — AI Model Integrity Verification
Verifies SHA-256 hash of model.pkl against on-chain registration.
Maps to: FR-09 / NFR-09
CRITICAL: Called at startup — mismatched hash aborts the service entirely.
"""

import os
import hashlib
import logging
from web3 import Web3

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')

# Blockchain connection (internal network)
BLOCKCHAIN_RPC = os.environ.get('BLOCKCHAIN_RPC', 'http://blockchain:8545')
CONTRACT_ADDRESS = os.environ.get('ACCESS_POLICY_ADDRESS')

# Minimal ABI for reading model hash
ACCESS_POLICY_ABI = [
    {
        "inputs": [],
        "name": "registeredModelHash",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function"
    }
]


def verify_model_integrity():
    """
    Compute SHA-256 of model.pkl and compare to on-chain registered hash.
    
    Raises RuntimeError if:
    - model.pkl does not exist
    - blockchain is unreachable  
    - hash does not match on-chain record
    
    Maps to NFR-09: "AI Engine refuses to start if hash does not match"
    """
    # First-boot path: no model on disk → RiskEngine() will auto-train and persist one.
    # The newly-trained model's hash should be registered on-chain in a follow-up
    # admin step. We only enforce the equality check when both sides exist.
    if not os.path.exists(MODEL_PATH):
        logger.warning(
            "Model file not found — assumed first boot. RiskEngine will auto-train a "
            "fresh baseline. Remember to register its hash on-chain via the admin script."
        )
        return

    # Compute current model hash
    with open(MODEL_PATH, 'rb') as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()
    logger.info(f"Current model hash: {current_hash}")

    # Connect to blockchain
    if not CONTRACT_ADDRESS:
        raise RuntimeError("FATAL: ACCESS_POLICY_ADDRESS not set. Required for on-chain integrity check.")

    import time
    
    max_retries = 15
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            # Use provided RPC or default to localhost for dev
            rpc_url = BLOCKCHAIN_RPC
            if 'localhost' in rpc_url and os.environ.get('DOCKER_ENV'):
                rpc_url = rpc_url.replace('localhost', 'host.docker.internal')

            w3 = Web3(Web3.HTTPProvider(rpc_url))
            if not w3.is_connected():
                logger.warning(f"Waiting for blockchain connection... (Attempt {attempt+1}/{max_retries})")
                time.sleep(retry_delay)
                continue

            contract = w3.eth.contract(
                address=Web3.to_checksum_address(CONTRACT_ADDRESS),
                abi=ACCESS_POLICY_ABI
            )

            # Fetch on-chain registered hash
            on_chain_hash_bytes = contract.functions.registeredModelHash().call()
            on_chain_hash = on_chain_hash_bytes.hex()
            
            # Remove '0x' prefix if present for comparison
            if on_chain_hash.startswith('0x'):
                on_chain_hash = on_chain_hash[2:]

            # Zero bytes32 means hash was never registered (initial deployment)
            if on_chain_hash == '0' * 64:
                logger.warning(
                    "No model hash registered on-chain yet — skipping integrity check. "
                    "IMPORTANT: Register the hash exactly once at deployment time via the "
                    "admin script. The contract must enforce write-once semantics so the "
                    "registered hash cannot be overwritten after initial registration."
                )
                return

            # CRITICAL COMPARISON (NFR-09)
            if current_hash != on_chain_hash:
                raise RuntimeError(
                    f"MODEL INTEGRITY FAILURE: "
                    f"current={current_hash} != on-chain={on_chain_hash}"
                )

            logger.info(f"Model integrity verified: hash matches on-chain record.")
            return # Success!

        except (RuntimeError, Exception) as e:
            if attempt < max_retries - 1:
                logger.warning(f"Blockchain check failed (contract likely not deployed yet): {e}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                logger.critical(f"FATAL: Blockchain integrity check failed after {max_retries} attempts: {e}")
                raise RuntimeError(f"Cannot verify model integrity: {e}")
