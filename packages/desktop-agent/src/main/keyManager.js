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
const snarkjs = require('snarkjs');

// Circuit paths
const CIRCUIT_WASM = path.join(__dirname, '../../circuits/identity_js/identity.wasm');
const CIRCUIT_ZKEY = path.join(__dirname, '../../circuits/identity_final.zkey');

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

async function generateZKProof(sessionNonce) {
    const sk = loadPrivateKey();
    try {
        if (!fs.existsSync(CIRCUIT_WASM) || !fs.existsSync(CIRCUIT_ZKEY)) {
            throw new Error('ZKP Circuit files missing. Proof generation failed.');
        }

        const input = {
            privateKey: BigInt('0x' + sk.toString('hex')),
            nonce: BigInt('0x' + Buffer.from(sessionNonce.replace(/-/g, ''), 'hex').toString('hex'))
        };

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            CIRCUIT_WASM,
            CIRCUIT_ZKEY
        );

        return { proof, publicSignals };
    } catch (err) {
        console.error('ZKP Generation Error:', err.message);
        throw err;
    } finally {
        sk.fill(0);
    }
}

module.exports = { enrollUser, isEnrolled, generateZKProof };
