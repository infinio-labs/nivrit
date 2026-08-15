import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ErrorBoundary } from './components/ErrorBoundary';
import { clearSession } from './session';
import './index.css';

/**
 * Errors thrown while the module graph loads (e.g. a failed WASM fetch) happen
 * before React mounts, so the ErrorBoundary never sees them — the result was a
 * blank page. Catch them at the window level and render the same recovery UI.
 */
function renderFatal(error: unknown) {
  console.error('Nivrit failed to start:', error);
  const root = document.getElementById('root');
  if (!root || root.hasChildNodes()) return;
  root.innerHTML = `
    <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;padding:1rem;font-family:system-ui,sans-serif">
      <div style="max-width:28rem;width:100%;background:#fff;border:1px solid #e2e8f0;border-radius:0.75rem;padding:1.5rem;box-shadow:0 10px 15px -3px rgb(0 0 0 / 0.1)">
        <h1 style="font-size:1.125rem;font-weight:600;color:#0f172a;margin:0 0 0.5rem">Something went wrong</h1>
        <p style="font-size:0.875rem;color:#64748b;margin:0 0 1rem">
          The page failed to load. Your secrets are unaffected — they are stored
          encrypted and never decrypted on the server. Reloading will sign you
          out, because your keys are held only in memory.
        </p>
        <button onclick="location.reload()" style="width:100%;padding:0.625rem;background:#0f172a;color:#fff;border:0;border-radius:0.5rem;font-size:0.875rem;font-weight:500;cursor:pointer">
          Reload and sign in again
        </button>
      </div>
    </div>`;
}

window.addEventListener('error', (event) => renderFatal(event.error ?? event.message));

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    {/* Drop the in-memory private key and project keys if the UI crashes: after
        an unexpected error we can no longer reason about the page's state, and
        keeping decrypted key material alive in it buys nothing. */}
    <ErrorBoundary onError={clearSession}>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
);
