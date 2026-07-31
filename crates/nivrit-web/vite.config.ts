import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import wasm from 'vite-plugin-wasm';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [wasm(), tailwindcss(), react()],
  build: {
    target: 'esnext',
  },
  // The crypto worker's wasm import uses top-level await, which the default
  // iife worker format can't emit.
  worker: {
    format: 'es',
    plugins: () => [wasm()],
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:4000',
        changeOrigin: true,
      },
    },
  },
});
