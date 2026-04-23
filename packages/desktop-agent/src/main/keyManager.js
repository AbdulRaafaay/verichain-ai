/**
 * VeriChain AI — Desktop Agent Key Manager
 * Handles cryptographic key generation and secure storage.
 * 
 * SECURITY CRITICAL:
 * - Private key wiped from memory immediately after ZKP generation
 * - All storage via OS-level encryption (safeStorage)
 * 
 * Maps to: FR-01, FR-02 / NFR-01, NFR-02
 */

'use strict';

const { safeStorage, app } = require('electron');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// We use a local file for the identity, but its content is encrypted by safeStorage
const IDENTITY_FILE = path.join(app.getPath('userData'), 'identity.enc');

function checkEncryptionAvailable() {
    if (!safeStorage.isEncryptionAvailable()) {
        throw new Error('OS Secure Storage (TPM/Keychain) is not available on this device.');
    }
}

async function enrollUser() {
    checkEncryptionAvailable();
    const privateKey = crypto.randomBytes(32);

    try {
        const publicKey = crypto.createHash('sha256').update(privateKey).digest('hex');
        const userHash = crypto.createHash('sha256').update(publicKey).digest('hex');

        // Encrypt and store private key (NFR-01)
        const encrypted = safeStorage.encryptString(privateKey.toString('hex'));
        fs.writeFileSync(IDENTITY_FILE, encrypted);

        return { publicKey, userHash };
    } finally {
        privateKey.fill(0); // Security: wipe from memory (NFR-01)
    }
}

function isEnrolled() {
    return fs.existsSync(IDENTITY_FILE);
}

function loadPrivateKey() {
    checkEncryptionAvailable();
    if (!fs.existsSync(IDENTITY_FILE)) {
        throw new Error('No enrolled identity found');
    }
    const encrypted = fs.readFileSync(IDENTITY_FILE);
    const hexKey = safeStorage.decryptString(encrypted);
    return Buffer.from(hexKey, 'hex');
}

/**
 * Generate a ZKP proof of identity knowledge.
 * MOCKED for development as SNARK circuits are large.
 */
async function generateZKProof(sessionNonce) {
    const sk = loadPrivateKey();
    try {
        // In real app, this would use snarkjs.groth16.fullProve
        // Mocking valid proof format for Gateway validation
        return {
            proof: {
                pi_a: ["0", "0", "0"],
                pi_b: [["0", "0"], ["0", "0"], ["0", "0"]],
                pi_c: ["0", "0", "0"],
                protocol: "groth16",
                curve: "bn128"
            },
            publicSignals: ["0"]
        };
    } finally {
        sk.fill(0);
    }
}

module.exports = { enrollUser, isEnrolled, generateZKProof };
