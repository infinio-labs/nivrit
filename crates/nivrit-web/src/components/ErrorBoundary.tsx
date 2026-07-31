import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle } from './icons';
import { Button, Card } from './ui';

interface Props {
  children: ReactNode;
  /** Called when the boundary catches, so the app can drop in-memory keys. */
  onError?: () => void;
}

interface State {
  error: Error | null;
}

/**
 * Catches render errors so a bug shows an explanation rather than a blank page.
 *
 * This matters more here than in an ordinary app. A white screen in a secret
 * manager is genuinely alarming: the user cannot tell a rendering bug from a
 * failed decryption or a compromised page, and their private key is sitting in
 * memory either way. Reloading is the correct recovery — the session is
 * memory-only by design, so a reload drops every key and returns to sign-in.
 *
 * Deliberately does not render the error message into the page body. Error
 * strings in this app can carry key identifiers and other material we would
 * rather not paint into the DOM or have a user screenshot into a bug report;
 * the detail goes to the console instead.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Nivrit UI error:', error, info.componentStack);
    this.props.onError?.();
  }

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 dark:bg-slate-950">
        <Card className="w-full max-w-md p-6 shadow-lg">
          <div className="mb-5 flex items-start gap-4">
            <div className="rounded-full bg-amber-100 p-2 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400">
              <AlertTriangle size={22} />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-slate-900 dark:text-white">
                Something went wrong
              </h1>
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                The page hit an unexpected error. Your secrets are unaffected — they are stored
                encrypted and were never decrypted on the server.
              </p>
              <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                Reloading will sign you out, because your keys are held only in memory. Technical
                detail has been written to the browser console.
              </p>
            </div>
          </div>
          <Button onClick={() => window.location.reload()} className="w-full">
            Reload and sign in again
          </Button>
        </Card>
      </div>
    );
  }
}
