'use strict';

const { safeStorage, app } = require('electron');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const snarkjs = require('snarkjs');

const CIRCUIT_WASM = path.join(__dirname, '../../circuits/identity_js/identity.wasm');
const CIRCUIT_ZKEY = path.join(__dirname, '../../circuits/identity_final.zkey');

// Identity file stores JSON: { encryptedKey: <base64>, userHash: <hex> }
const IDENTITY_FILE = path.join(app.getPath('userData'), 'identity.enc');

function checkEncryptionAvailable() {
    if (!safeStorage.isEncryptionAvailable()) {
        throw new Error('OS Secure Storage (TPM/Keychain) is not available on this device.');
    }
}

async function enrollUser() {
    checkEncryptionAvailable();
    // 31 bytes (248 bits) keeps the value below the BN128 scalar field (~254 bits)
    // preventing arithmetic overflow inside the Groth16/Poseidon circuit.
    const privateKey = crypto.randomBytes(31);

    try {
        const publicKey = crypto.createHash('sha256').update(privateKey).digest('hex');
        const userHash = crypto.createHash('sha256').update(publicKey).digest('hex');

        const encrypted = safeStorage.encryptString(privateKey.toString('hex'));
        const data = {
            encryptedKey: encrypted.toString('base64'),
            userHash
        };
        fs.writeFileSync(IDENTITY_FILE, JSON.stringify(data));

        return { publicKey, userHash };
    } finally {
        privateKey.fill(0);
    }
}

function isEnrolled() {
    return fs.existsSync(IDENTITY_FILE);
}

function getUserHash() {
    if (!fs.existsSync(IDENTITY_FILE)) return null;
    try {
        const data = JSON.parse(fs.readFileSync(IDENTITY_FILE, 'utf-8'));
        return data.userHash || null;
    } catch {
        return null;
    }
}

function loadPrivateKey() {
    checkEncryptionAvailable();
    if (!fs.existsSync(IDENTITY_FILE)) {
        throw new Error('No enrolled identity found');
    }
    const data = JSON.parse(fs.readFileSync(IDENTITY_FILE, 'utf-8'));
    const encrypted = Buffer.from(data.encryptedKey, 'base64');
    const hexKey = safeStorage.decryptString(encrypted);
    return Buffer.from(hexKey, 'hex');
}

async function generateZKProof(sessionNonce) {
    // Dev mode: return mock proof when circuit files are not compiled yet
    if (!fs.existsSync(CIRCUIT_WASM) || !fs.existsSync(CIRCUIT_ZKEY)) {
        console.warn('DEV MODE: ZKP circuit files missing — returning mock proof. Run scripts/compile-circuits.sh for production.');
        return {
            proof: { pi_a: ['0'], pi_b: [['0', '0'], ['0', '0']], pi_c: ['0'], protocol: 'groth16' },
            publicSignals: ['0']
        };
    }

    const sk = loadPrivateKey();
    try {
        const input = {
            privateKey: BigInt('0x' + sk.toString('hex')),
            nonce: BigInt('0x' + sessionNonce)
        };

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            CIRCUIT_WASM,
            CIRCUIT_ZKEY
        );

        return { proof, publicSignals };
    } finally {
        sk.fill(0);
    }
}

module.exports = { enrollUser, isEnrolled, getUserHash, generateZKProof };
