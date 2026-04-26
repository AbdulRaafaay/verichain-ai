/**
 * blockchain.service.ts
 * 
 * Purpose: Provides high-level abstractions for interacting with the Ethereum/Hardhat blockchain.
 * Handles identity anchoring, access policy verification, and event streaming.
 * 
 * Security Controls (NFR-03, NFR-05):
 * - Fail-Closed Logic: Denies access if the blockchain is unreachable.
 * - Integrity: Every session and policy change is anchored to the chain.
 * - Auditability: Fetches immutable on-chain events for the Trust Dashboard.
 */

import { ethers } from 'ethers';
import { logger } from '../utils/logger';

const ACCESS_POLICY_ABI = [
    "function isAccessAllowed(bytes32 userHash, bytes32 resourceHash) external view returns (bool)",
    "function checkAccess(bytes32 userHash, bytes32 resourceHash) external returns (bool)",
    "function createSession(bytes32 sessionId, bytes32 userHash) external",
    "function revokeSession(bytes32 sessionId, string calldata reason) external",
    "function triggerAlert(string calldata alertType, bytes32 data) external",
    "function proposeChange(bytes32 changeHash) external",
    "function approveChange(bytes32 changeHash, bytes32 userHash, bytes32 resourceHash, bool grant) external",
    "function registeredModelHash() external view returns (bytes32)",
    "event AccessDecision(bytes32 indexed userHash, bytes32 indexed resourceHash, bool allowed, uint256 timestamp)",
    "event SessionCreated(bytes32 indexed sessionId, bytes32 indexed userHash, uint256 timestamp)",
    "event SessionRevoked(bytes32 indexed sessionId, string reason, uint256 timestamp)",
    "event SystemAlert(string alertType, bytes32 indexed data, address reporter, uint256 timestamp)",
    "event PolicyChangeProposed(bytes32 indexed changeId, address proposer, uint256 timestamp)",
    "event PolicyChangeExecuted(bytes32 indexed changeId, uint256 timestamp)"
];

const AUDIT_LEDGER_ABI = [
    "function anchorMerkleRoot(bytes32 root, uint256 logCount) external",
    "function getLatestRoot() external view returns (bytes32 root, uint256 timestamp)",
    "event MerkleRootAnchored(bytes32 indexed root, uint256 timestamp, uint256 logCount, address indexed anchor, uint256 indexed entryIndex)"
];

export class BlockchainService {
    public static provider: ethers.JsonRpcProvider;
    private static wallet: ethers.Wallet;
    public static accessPolicy: ethers.Contract;
    public static auditLedger: ethers.Contract;

    // Serialize all outbound transactions so concurrent calls cannot collide on nonce
    private static txQueue: Promise<any> = Promise.resolve();

    /**
     * Enqueue a transaction-producing function.  The returned promise resolves once
     * the tx is mined.  If the tx fails, the error is propagated but the queue is
     * unblocked so subsequent transactions can still proceed.
     */
    static async sendTx<T>(fn: () => Promise<T>): Promise<T> {
        const prev = this.txQueue;
        let settle!: () => void;
        // Extend the queue; swallow its rejection so later callers are not blocked
        this.txQueue = new Promise<void>(res => { settle = res; });
        await prev.catch(() => {});
        try {
            const result = await fn();
            settle();
            return result;
        } catch (err) {
            settle();
            throw err;
        }
    }

    /**
     * Initializes the blockchain provider and contract instances.
     * @throws Error if required environment variables (PRIVATE_KEY, ADDRESSES) are missing.
     */
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

    /**
     * Checks if a user is allowed to access a resource based on on-chain policy.
     * @param userHash - The SHA256 hash of the client's public identity.
     * @param resourceHash - The identifier for the protected file/resource.
     * @returns boolean - True if access is explicitly granted, False otherwise (Fail-Closed).
     */
    static async checkAccess(userHash: string, resourceHash: string): Promise<boolean> {
        try {
            return await this.accessPolicy.checkAccess(`0x${userHash}`, `0x${resourceHash}`);
        } catch (err) {
            logger.error('Blockchain Access Check Failed (Fail-Closed)', { error: (err as Error).message });
            return false;
        }
    }

    /**
     * Convert a UUID or short hex string to a zero-right-padded bytes32 hex value.
     * UUID (16 bytes / 32 hex) → padded to 32 bytes / 64 hex so ethers v6 accepts it.
     * Public so all callers route through one canonical implementation.
     */
    static toBytes32(hex: string): string {
        const clean = hex.replace(/^0x/, '').replace(/-/g, '').toLowerCase();
        return '0x' + clean.slice(0, 64).padEnd(64, '0');
    }

    /**
     * Anchors a new session ID to the blockchain for non-repudiation.
     * @param sessionIdHash - Unique session identifier (UUID or hex string).
     * @param userHash - User identity hash (SHA-256, already 32 bytes).
     */
    static async createSession(sessionIdHash: string, userHash: string) {
        return this.sendTx(async () => {
            const tx = await this.accessPolicy.createSession(
                this.toBytes32(sessionIdHash),
                `0x${userHash}`
            );
            const receipt = await tx.wait();
            logger.info(`Session anchored on-chain: ${sessionIdHash}`);
            return receipt;
        });
    }

    /**
     * Aggregates and normalises past events from all relevant smart contracts.
     * Returns the canonical dashboard event shape: { id, name, tx, block, args, timestamp }.
     */
    static async getPastEvents(): Promise<any[]> {
        const events: any[] = [];

        try {
            const toEntry = (ev: any, name: string) => ({
                id:        (ev.transactionHash || '') + ':' + (ev.index ?? ev.logIndex ?? Math.random()),
                name,
                tx:        ev.transactionHash,
                block:     ev.blockNumber,
                timestamp: new Date().toISOString(), // enriched below
                args:      ev.args ? Object.fromEntries(
                    Object.entries(ev.args)
                        .filter(([k]) => isNaN(Number(k)))
                        .map(([k, v]) => [k, typeof v === 'bigint' ? v.toString() : v])
                ) : {},
            });

            const [
                sessionCreated, sessionRevoked, accessDecision,
                systemAlert, policyProposed, policyExecuted, merkleAnchored,
            ] = await Promise.all([
                this.accessPolicy.queryFilter(this.accessPolicy.filters.SessionCreated()).catch(() => []),
                this.accessPolicy.queryFilter(this.accessPolicy.filters.SessionRevoked()).catch(() => []),
                this.accessPolicy.queryFilter(this.accessPolicy.filters.AccessDecision()).catch(() => []),
                this.accessPolicy.queryFilter(this.accessPolicy.filters.SystemAlert()).catch(() => []),
                this.accessPolicy.queryFilter(this.accessPolicy.filters.PolicyChangeProposed()).catch(() => []),
                this.accessPolicy.queryFilter(this.accessPolicy.filters.PolicyChangeExecuted()).catch(() => []),
                this.auditLedger.queryFilter(this.auditLedger.filters.MerkleRootAnchored()).catch(() => []),
            ]);

            const allRaw = [
                ...sessionCreated.map((e: any) => toEntry(e, 'SessionCreated')),
                ...sessionRevoked.map((e: any) => toEntry(e, 'SessionRevoked')),
                ...accessDecision.map((e: any) => toEntry(e, 'AccessDecision')),
                ...systemAlert.map((e: any) => toEntry(e, 'SystemAlert')),
                ...policyProposed.map((e: any) => toEntry(e, 'PolicyChangeProposed')),
                ...policyExecuted.map((e: any) => toEntry(e, 'PolicyChangeExecuted')),
                ...merkleAnchored.map((e: any) => toEntry(e, 'MerkleRootAnchored')),
            ];

            const blockNums = [...new Set(allRaw.map(e => e.block))];
            const blockTimes: Record<number, string> = {};
            await Promise.all(blockNums.map(async bn => {
                try {
                    const block = await this.provider.getBlock(bn);
                    if (block) blockTimes[bn] = new Date(Number(block.timestamp) * 1000).toISOString();
                } catch { /* skip */ }
            }));

            for (const e of allRaw) {
                if (blockTimes[e.block]) e.timestamp = blockTimes[e.block];
                events.push(e);
            }

            events.sort((a, b) => b.block - a.block);
        } catch (err) {
            logger.error('getPastEvents failed', { error: (err as Error).message });
        }

        return events;
    }

    /**
     * Read-only access policy lookup. Used for per-request policy enforcement.
     * Calls a `view` function — no transaction, no gas, no nonce involvement.
     * Fail-closed: any error denies access.
     */
    static async isAccessAllowed(userHash: string, resourceHash: string): Promise<boolean> {
        try {
            return await this.accessPolicy.isAccessAllowed(userHash, resourceHash);
        } catch (err) {
            logger.error('isAccessAllowed query failed (fail-closed)', { error: (err as Error).message });
            return false;
        }
    }

    /**
     * Revoke a session on-chain via the serialised tx queue.
     * Wrapper around accessPolicy.revokeSession that ensures nonce safety.
     */
    static async revokeSession(sessionIdHex: string, reason: string): Promise<void> {
        await this.sendTx(async () => {
            const tx = await this.accessPolicy.revokeSession(this.toBytes32(sessionIdHex), reason);
            return tx.wait();
        });
    }
}
