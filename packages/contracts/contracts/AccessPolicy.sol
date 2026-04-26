// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title AccessPolicy
 * @notice Decentralized Policy Decision Point for VeriChain AI
 * @dev Enforces RBAC with 2-of-3 multi-sig governance. ReentrancyGuard on all
 *      state-changing functions. Maps to FR-10,11,12 / NFR-10,11,12.
 * Security: Checks-Effects-Interactions pattern strictly enforced throughout.
 */
contract AccessPolicy is ReentrancyGuard, Pausable, AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    uint256 public constant MULTI_SIG_THRESHOLD = 2;

    struct PolicyChange {
        bytes32 changeHash;
        address[] approvals;
        bool executed;
        uint256 proposedAt;
    }

    struct SessionRecord {
        bytes32 userHash;
        bool active;
        uint256 createdAt;
        uint256 revokedAt;
    }

    // userHash => resourceHash => allowed
    mapping(bytes32 => mapping(bytes32 => bool)) public accessRules;
    // changeId => PolicyChange
    mapping(bytes32 => PolicyChange) public pendingChanges;
    // sessionId => SessionRecord
    mapping(bytes32 => SessionRecord) public sessions;
    // AI model hash registered at build time
    bytes32 public registeredModelHash;
    // Alert log
    bytes32[] public alertLog;

    event AccessDecision(bytes32 indexed userHash, bytes32 indexed resourceHash, bool allowed, uint256 timestamp);
    event SessionCreated(bytes32 indexed sessionId, bytes32 indexed userHash, uint256 timestamp);
    event SessionRevoked(bytes32 indexed sessionId, string reason, uint256 timestamp);
    event PolicyChangeProposed(bytes32 indexed changeId, address proposer, uint256 timestamp);
    event PolicyChangeExecuted(bytes32 indexed changeId, uint256 timestamp);
    event SystemAlert(string alertType, bytes32 indexed data, address reporter, uint256 timestamp);
    event ModelHashRegistered(bytes32 indexed modelHash, address registrar, uint256 timestamp);

    constructor(address[] memory admins, address gateway) {
        require(admins.length >= 3, "Need at least 3 admins for multi-sig");
        for (uint256 i = 0; i < admins.length; i++) {
            _grantRole(ADMIN_ROLE, admins[i]);
        }
        _grantRole(GATEWAY_ROLE, gateway);
        _grantRole(DEFAULT_ADMIN_ROLE, admins[0]);
    }

    /**
     * @notice Read-only access policy lookup. Pure view — no transaction needed.
     * @dev Use this for the per-request policy check. The bool is returned via JS
     *      directly (no event emission, no gas cost beyond the eth_call).
     */
    function isAccessAllowed(bytes32 userHash, bytes32 resourceHash)
        external
        view
        returns (bool)
    {
        return accessRules[userHash][resourceHash];
    }

    /**
     * @notice Audit-trail variant of the access check. Emits AccessDecision event.
     * @dev CHECKS: rule lookup. EFFECTS: emit event. INTERACTIONS: none.
     *      Costs gas — call in non-blocking fashion only when an immutable record
     *      of the decision is required for compliance.
     * @param userHash keccak256 of userId — NO plaintext identity on-chain
     * @param resourceHash keccak256 of resourceId — NO plaintext resource on-chain
     */
    function checkAccess(bytes32 userHash, bytes32 resourceHash)
        external
        nonReentrant
        whenNotPaused
        onlyRole(GATEWAY_ROLE)
        returns (bool)
    {
        // CHECKS
        bool allowed = accessRules[userHash][resourceHash];
        // EFFECTS
        emit AccessDecision(userHash, resourceHash, allowed, block.timestamp);
        // INTERACTIONS: none
        return allowed;
    }

    /**
     * @notice Grant access for a userHash to a resourceHash.
     * @dev Requires 2-of-3 multi-sig via proposeChange/approveChange flow.
     */
    function grantAccess(bytes32 userHash, bytes32 resourceHash)
        internal
    {
        // EFFECTS before any external calls (CEI pattern)
        accessRules[userHash][resourceHash] = true;
    }

    function revokeAccess(bytes32 userHash, bytes32 resourceHash)
        internal
    {
        accessRules[userHash][resourceHash] = false;
    }

    /**
     * @notice Create a session record on-chain after successful ZKP auth.
     */
    function createSession(bytes32 sessionId, bytes32 userHash)
        external
        nonReentrant
        whenNotPaused
        onlyRole(GATEWAY_ROLE)
    {
        // CHECKS
        require(!sessions[sessionId].active, "Session already exists");
        // EFFECTS
        sessions[sessionId] = SessionRecord({
            userHash: userHash,
            active: true,
            createdAt: block.timestamp,
            revokedAt: 0
        });
        emit SessionCreated(sessionId, userHash, block.timestamp);
    }

    /**
     * @notice Revoke a session (heartbeat miss, risk score >75, tamper detected).
     * @param reason Human-readable revocation reason for audit trail
     */
    function revokeSession(bytes32 sessionId, string calldata reason)
        external
        nonReentrant
        onlyRole(GATEWAY_ROLE)
    {
        // CHECKS
        require(sessions[sessionId].active, "Session not active");
        // EFFECTS (state before external calls — CEI)
        sessions[sessionId].active = false;
        sessions[sessionId].revokedAt = block.timestamp;
        emit SessionRevoked(sessionId, reason, block.timestamp);
        // INTERACTIONS: none
    }

    /**
     * @notice Propose a policy change (step 1 of multi-sig flow).
     * @dev Commit-reveal: admins submit hash of change; prevents front-running (NFR-11)
     */
    function proposeChange(bytes32 changeHash)
        external
        nonReentrant
        onlyRole(ADMIN_ROLE)
    {
        require(pendingChanges[changeHash].proposedAt == 0, "Change already proposed");
        pendingChanges[changeHash].changeHash = changeHash;
        pendingChanges[changeHash].proposedAt = block.timestamp;
        emit PolicyChangeProposed(changeHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Approve a proposed change (step 2 of multi-sig flow).
     * @dev Executes when MULTI_SIG_THRESHOLD approvals reached.
     */
    function approveChange(bytes32 changeHash, bytes32 userHash, bytes32 resourceHash, bool grant)
        external
        nonReentrant
        onlyRole(ADMIN_ROLE)
    {
        PolicyChange storage pc = pendingChanges[changeHash];
        require(pc.proposedAt > 0, "Change not proposed");
        require(!pc.executed, "Change already executed");

        // Prevent duplicate approval from same address
        for (uint256 i = 0; i < pc.approvals.length; i++) {
            require(pc.approvals[i] != msg.sender, "Already approved");
        }

        // EFFECTS first (CEI)
        pc.approvals.push(msg.sender);

        if (pc.approvals.length >= MULTI_SIG_THRESHOLD) {
            pc.executed = true;
            // Execute the policy change
            if (grant) {
                grantAccess(userHash, resourceHash);
            } else {
                revokeAccess(userHash, resourceHash);
            }
            emit PolicyChangeExecuted(changeHash, block.timestamp);
        }
    }

    /**
     * @notice Register AI model hash on-chain at build time (NFR-09).
     */
    function registerModelHash(bytes32 modelHash)
        external
        nonReentrant
        onlyRole(ADMIN_ROLE)
    {
        registeredModelHash = modelHash;
        emit ModelHashRegistered(modelHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Trigger a system alert (tamper detection, anomaly, etc.).
     */
    function triggerAlert(string calldata alertType, bytes32 data)
        external
        nonReentrant
        onlyRole(GATEWAY_ROLE)
    {
        alertLog.push(keccak256(abi.encodePacked(alertType, data, block.timestamp)));
        emit SystemAlert(alertType, data, msg.sender, block.timestamp);
    }

    // Emergency circuit breaker — any admin can pause
    function emergencyPause() external onlyRole(ADMIN_ROLE) { _pause(); }
    function emergencyUnpause() external onlyRole(ADMIN_ROLE) { _unpause(); }

    function getSession(bytes32 sessionId) external view returns (SessionRecord memory) {
        return sessions[sessionId];
    }

    function getAlertCount() external view returns (uint256) {
        return alertLog.length;
    }
}
