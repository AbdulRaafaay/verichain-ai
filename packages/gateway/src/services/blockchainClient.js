'use strict';

const { ethers } = require('ethers');
const winston = require('winston');

const logger = winston.createLogger({
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

let provider;
let wallet;
let accessPolicy;
let auditLedger;

const ACCESS_POLICY_ABI = [
    "function checkAccess(bytes32 userHash, bytes32 resourceHash) external returns (bool)",
    "function createSession(bytes32 sessionId, bytes32 userHash) external",
    "function revokeSession(bytes32 sessionId, string calldata reason) external",
    "function triggerAlert(string calldata alertType, bytes32 data) external",
    "function registeredModelHash() external view returns (bytes32)",
    "event AccessDecision(bytes32 indexed userHash, bytes32 indexed resourceHash, bool allowed, uint256 timestamp)",
    "event SessionCreated(bytes32 indexed sessionId, bytes32 indexed userHash, uint256 timestamp)",
    "event SessionRevoked(bytes32 indexed sessionId, string reason, uint256 timestamp)"
];

const AUDIT_LEDGER_ABI = [
    "function anchorMerkleRoot(bytes32 root, uint256 logCount) external",
    "function getLatestRoot() external view returns (bytes32 root, uint256 timestamp)",
    "event MerkleRootAnchored(bytes32 indexed root, uint256 timestamp, uint256 logCount, address indexed anchor, uint256 indexed entryIndex)"
];

async function initBlockchainClient({ rpcUrl, accessPolicyAddress, auditLedgerAddress, gatewayPrivateKey }) {
    try {
        provider = new ethers.JsonRpcProvider(rpcUrl);
        wallet = new ethers.Wallet(gatewayPrivateKey, provider);
        
        accessPolicy = new ethers.Contract(accessPolicyAddress, ACCESS_POLICY_ABI, wallet);
        auditLedger = new ethers.Contract(auditLedgerAddress, AUDIT_LEDGER_ABI, wallet);

        const network = await provider.getNetwork();
        logger.info('Blockchain client initialized', { 
            chainId: network.chainId.toString(),
            gatewayAddress: wallet.address 
        });
    } catch (err) {
        logger.error('Failed to initialize blockchain client', { error: err.message });
        throw err;
    }
}

function getBlockchainClient() {
    if (!accessPolicy || !auditLedger) {
        throw new Error('Blockchain client not initialized');
    }
    return { accessPolicy, auditLedger, provider, wallet };
}

module.exports = { initBlockchainClient, getBlockchainClient };
