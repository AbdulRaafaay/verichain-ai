// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title AuditLedger
 * @notice Immutable Merkle root anchoring for tamper-proof audit trail.
 * @dev Maps to FR-13, FR-14, NFR-13, NFR-14.
 *      Every 60 seconds the Gateway anchors a Merkle root of all log batches.
 *      Any alteration to MongoDB logs causes a Merkle mismatch detectable here.
 */
contract AuditLedger is ReentrancyGuard, AccessControl {
    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");

    struct MerkleEntry {
        bytes32 root;
        uint256 timestamp;
        uint256 logCount;
        address anchor;
    }

    MerkleEntry[] public merkleHistory;
    mapping(bytes32 => bool) public rootExists;

    event MerkleRootAnchored(
        bytes32 indexed root,
        uint256 timestamp,
        uint256 logCount,
        address indexed anchor,
        uint256 indexed entryIndex
    );
    event TamperAlertEmitted(
        bytes32 indexed expectedRoot,
        bytes32 indexed computedRoot,
        uint256 timestamp
    );

    constructor(address gateway) {
        _grantRole(GATEWAY_ROLE, gateway);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Anchor a Merkle root of the current log batch.
     * @dev Called by Gateway every 60 seconds (NFR-13).
     *      Once anchored, root is immutable — no admin can overwrite or delete.
     * @param root SHA-256 Merkle root of the log batch
     * @param logCount Number of logs in this batch (for verification)
     */
    function anchorMerkleRoot(bytes32 root, uint256 logCount)
        external
        nonReentrant
        onlyRole(GATEWAY_ROLE)
    {
        require(!rootExists[root], "Root already anchored");
        // EFFECTS before external calls (CEI)
        rootExists[root] = true;
        uint256 entryIndex = merkleHistory.length;
        merkleHistory.push(MerkleEntry({
            root: root,
            timestamp: block.timestamp,
            logCount: logCount,
            anchor: msg.sender
        }));
        emit MerkleRootAnchored(root, block.timestamp, logCount, msg.sender, entryIndex);
    }

    /**
     * @notice Get the most recently anchored Merkle root.
     */
    function getLatestRoot() external view returns (bytes32 root, uint256 timestamp) {
        require(merkleHistory.length > 0, "No roots anchored yet");
        MerkleEntry storage latest = merkleHistory[merkleHistory.length - 1];
        return (latest.root, latest.timestamp);
    }

    /**
     * @notice Verify a log entry exists in a given Merkle tree.
     * @param leaf SHA-256 hash of the log entry JSON
     * @param proof Merkle proof path (sibling hashes)
     * @param root The anchored root to verify against
     */
    function verifyLogEntry(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) external pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (computed <= proof[i]) {
                computed = keccak256(abi.encodePacked(computed, proof[i]));
            } else {
                computed = keccak256(abi.encodePacked(proof[i], computed));
            }
        }
        return computed == root;
    }

    /**
     * @notice Emit a tamper alert when Merkle mismatch is detected (NFR-14).
     */
    function emitTamperAlert(bytes32 expectedRoot, bytes32 computedRoot)
        external
        nonReentrant
        onlyRole(GATEWAY_ROLE)
    {
        emit TamperAlertEmitted(expectedRoot, computedRoot, block.timestamp);
    }

    function getRootCount() external view returns (uint256) {
        return merkleHistory.length;
    }

    function getRootAt(uint256 index) external view returns (MerkleEntry memory) {
        require(index < merkleHistory.length, "Index out of bounds");
        return merkleHistory[index];
    }
}
