'use strict';

const { z } = require('zod');
const dotenv = require('dotenv');
const path = require('path');

function loadEnv() {
    dotenv.config({ path: path.join(__dirname, '../../../../.env') });
    dotenv.config({ path: path.join(__dirname, '../../../../.env.local') });

    const schema = z.object({
        NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
        GATEWAY_PORT: z.string().default('8443'),
        MONGODB_URI: z.string(),
        REDIS_URL: z.string(),
        BLOCKCHAIN_RPC: z.string(),
        ACCESS_POLICY_ADDRESS: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
        AUDIT_LEDGER_ADDRESS: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
        GATEWAY_PRIVATE_KEY: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
        AI_ENGINE_URL: z.string().url(),
        AI_HMAC_SECRET: z.string().min(32),
        DESKTOP_AGENT_ORIGIN: z.string().url(),
        TRUST_DASHBOARD_ORIGIN: z.string().url(),
        HMAC_SECRET: z.string().min(32),
        JWT_SECRET: z.string().min(32),
    });

    const parsed = schema.safeParse(process.env);

    if (!parsed.success) {
        console.error('❌ Invalid environment variables:', JSON.stringify(parsed.error.format(), null, 2));
        process.exit(1);
    }

    return parsed.data;
}

module.exports = { loadEnv };
