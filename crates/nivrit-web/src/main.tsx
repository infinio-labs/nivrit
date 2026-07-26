import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ErrorBoundary } from './components/ErrorBoundary';
import { clearSession } from './session';
import './index.css';

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
