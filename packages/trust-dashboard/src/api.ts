/**
 * api.ts — Pre-configured axios instance for the Trust Dashboard.
 *
 * Attaches the X-Admin-Key header (sourced from REACT_APP_ADMIN_API_KEY) to
 * every request so admin gateway endpoints can authenticate the dashboard.
 * Using a shared instance ensures the key is set consistently in one place and
 * prevents accidental omission in individual page components.
 */

import axios from 'axios';

const GATEWAY_URL  = process.env.REACT_APP_GATEWAY_URL  || 'https://localhost:8443';
const ADMIN_KEY    = process.env.REACT_APP_ADMIN_API_KEY || 'dev-admin-key';

// Security note: REACT_APP_ADMIN_API_KEY is embedded in the JS bundle at build time.
// This is a known demo limitation. In production, replace with short-lived JWT tokens
// issued by a server-side auth endpoint (OAuth2 client-credentials flow).
const api = axios.create({
    baseURL:         GATEWAY_URL,
    withCredentials: true,
    headers: {
        'X-Admin-Key': ADMIN_KEY,
    },
});

export default api;
export { GATEWAY_URL, ADMIN_KEY };
