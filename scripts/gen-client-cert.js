#!/usr/bin/env node
/**
 * gen-client-cert.js
 *
 * Generates a Desktop Agent client certificate (client.key + client.crt)
 * signed by the existing CA in the certs/ folder.
 *
 * Works on Windows without a system OpenSSL installation by detecting the
 * copy bundled with Git for Windows, then falls back to any openssl on PATH.
 *
 * Usage:
 *   node scripts/gen-client-cert.js
 */

'use strict';

const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

// ── Resolve paths ─────────────────────────────────────────────────────────────
const ROOT     = path.resolve(__dirname, '..');
const CERT_DIR = path.join(ROOT, 'certs');
const CA_KEY   = path.join(CERT_DIR, 'ca.key');
const CA_CRT   = path.join(CERT_DIR, 'ca.crt');
const CLI_KEY  = path.join(CERT_DIR, 'client.key');
const CLI_CSR  = path.join(CERT_DIR, 'client.csr');
const CLI_CRT  = path.join(CERT_DIR, 'client.crt');

// ── Pre-flight checks ─────────────────────────────────────────────────────────
if (!fs.existsSync(CA_KEY) || !fs.existsSync(CA_CRT)) {
    console.error('ERROR: CA files not found in certs/');
    console.error('       Expected: certs/ca.key  and  certs/ca.crt');
    console.error('       Run docker-setup-certs.sh first (docker compose up setup)');
    process.exit(1);
}

if (fs.existsSync(CLI_CRT) && fs.existsSync(CLI_KEY)) {
    console.log('Client certificate already exists — skipping generation.');
    console.log('  certs/client.crt');
    console.log('  certs/client.key');
    console.log('\nDelete those files and re-run to regenerate.');
    process.exit(0);
}

// ── Find OpenSSL ──────────────────────────────────────────────────────────────
function findOpenSSL() {
    // 1. System PATH
    try {
        execSync('openssl version', { stdio: 'pipe' });
        return 'openssl';
    } catch { /* not on PATH */ }

    // 2. Git for Windows (most common on Windows dev machines)
    const gitPaths = [
        'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
        'C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe',
    ];
    for (const p of gitPaths) {
        if (fs.existsSync(p)) return `"${p}"`;
    }

    // 3. Common standalone installs
    const standaloneWin = [
        'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe',
        'C:\\OpenSSL-Win64\\bin\\openssl.exe',
        'C:\\OpenSSL\\bin\\openssl.exe',
    ];
    for (const p of standaloneWin) {
        if (fs.existsSync(p)) return `"${p}"`;
    }

    return null;
}

const openssl = findOpenSSL();
if (!openssl) {
    console.error('ERROR: OpenSSL not found.');
    console.error('       Install Git for Windows (includes OpenSSL) or standalone OpenSSL.');
    console.error('       https://git-scm.com/download/win');
    process.exit(1);
}

console.log(`Using OpenSSL: ${openssl}`);

// ── Helper ─────────────────────────────────────────────────────────────────────
function run(cmd) {
    console.log(`  > ${cmd}`);
    execSync(cmd, { stdio: 'inherit' });
}

// ── Generate client key + CSR + cert ─────────────────────────────────────────
console.log('\n[1/3] Generating client private key...');
run(`${openssl} genrsa -out "${CLI_KEY}" 2048`);

console.log('\n[2/3] Creating Certificate Signing Request...');
run(
    `${openssl} req -new -key "${CLI_KEY}" -out "${CLI_CSR}"` +
    ` -subj "/C=PK/O=VeriChainAI/CN=desktop-agent"`
);

console.log('\n[3/3] Signing client certificate with CA...');
run(
    `${openssl} x509 -req -in "${CLI_CSR}"` +
    ` -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial` +
    ` -out "${CLI_CRT}" -days 365 -sha256`
);

// Clean up CSR (not needed at runtime)
if (fs.existsSync(CLI_CSR)) fs.unlinkSync(CLI_CSR);

// ── Done ──────────────────────────────────────────────────────────────────────
console.log('\n✓  Client certificate generated successfully:');
console.log(`   ${CLI_KEY}`);
console.log(`   ${CLI_CRT}`);
console.log('\nRestart the Desktop Agent — it will now use full mTLS.');
