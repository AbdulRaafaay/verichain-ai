import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: 'src/renderer',
  plugins: [react()],
  define: {
    // Vite doesn't inject process.env — polyfill the vars the renderer needs
    'process.env.REACT_APP_GATEWAY_URL': JSON.stringify(process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443'),
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'development'),
  },
  server: {
    port: 3000,
    strictPort: true,
  },
  build: {
    outDir: '../../dist/renderer',
    emptyOutDir: true,
  },
});
