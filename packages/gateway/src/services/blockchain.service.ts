import { ethers } from 'ethers';
import { logger } from '../utils/logger';

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

export class BlockchainService {
    private static provider: ethers.JsonRpcProvider;
    private static wallet: ethers.Wallet;
    public static accessPolicy: ethers.Contract;
    public static auditLedger: ethers.Contract;

    static async init() {
        const rpcUrl = process.env.BLOCKCHAIN_RPC || 'http://blockchain:8545';
        const accessPolicyAddress = process.env.ACCESS_POLICY_ADDRESS;
        const auditLedgerAddress = process.env.AUDIT_LEDGER_ADDRESS;
        const gatewayPrivateKey = process.env.GATEWAY_PRIVATE_KEY;

        if (!accessPolicyAddress || !auditLedgerAddress || !gatewayPrivateKey) {
            throw new Error('Blockchain configuration missing (ADDRESSES or PRIVATE_KEY)');
        }

        this.provider = new ethers.JsonRpcProvider(rpcUrl);
        this.wallet = new ethers.Wallet(gatewayPrivateKey, this.provider);
        
        this.accessPolicy = new ethers.Contract(accessPolicyAddress, ACCESS_POLICY_ABI, this.wallet);
        this.auditLedger = new ethers.Contract(auditLedgerAddress, AUDIT_LEDGER_ABI, this.wallet);

        const network = await this.provider.getNetwork();
        logger.info('Blockchain Service initialized', { 
            chainId: network.chainId.toString(),
            gatewayAddress: this.wallet.address 
        });
    }

    static async checkAccess(userHash: string, resourceHash: string): Promise<boolean> {
        try {
            return await this.accessPolicy.checkAccess(`0x${userHash}`, `0x${resourceHash}`);
        } catch (err) {
            logger.error('Blockchain Access Check Failed (Fail-Closed)', { error: (err as Error).message });
            return false;
        }
    }

    static async createSession(sessionIdHash: string, userHash: string) {
        try {
            const tx = await this.accessPolicy.createSession(`0x${sessionIdHash}`, `0x${userHash}`);
            await tx.wait();
            logger.info(`Session anchored on-chain: ${sessionIdHash}`);
        } catch (err) {
            logger.error('Blockchain Session Creation Failed', { error: (err as Error).message });
            throw err;
        }
    }
}
