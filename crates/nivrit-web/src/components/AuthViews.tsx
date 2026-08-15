import { KeyRound, Loader2, Lock, Mail, Shield } from './icons';
import { Button, Card, Input, Label } from './ui';
import { AuthLayout } from './AuthLayout';
import { AuthScreen } from './AuthScreen';
import { clearPendingToken } from '../session';

/** Which pre-dashboard screen is showing. */
export type AuthView = 'auth' | 'unlock' | 'mfa' | 'oauth' | 'forgot' | 'reset';

interface AuthViewsProps {
  view: AuthView;
  isRegister: boolean;
  setIsRegister: (v: boolean) => void;
  email: string;
  setEmail: (v: string) => void;
  password: string;
  setPassword: (v: string) => void;
  name: string;
  setName: (v: string) => void;
  /** Non-empty while a request is in flight; also the label to show. */
  busy: string;
  totpCode: string;
  setTotpCode: (v: string) => void;
  recoveryCodeInput: string;
  setRecoveryCodeInput: (v: string) => void;
  handleAuth: (e: React.FormEvent) => void;
  handleUnlock: (e: React.FormEvent) => void;
  handleMfa: (e: React.FormEvent) => void;
  handleOAuth: (provider: 'google' | 'github') => void;
  handleOAuthComplete: (e: React.FormEvent) => void;
  handleForgot: (e: React.FormEvent) => void;
  handleReset: (e: React.FormEvent) => void;
  setView: (v: AuthView | 'dashboard') => void;
}

/**
 * The screens shown before a session exists: sign in, register, the MFA
 * challenge, OAuth completion, and the two password-reset steps.
 *
 * Split out of App purely for size — these five views were about a fifth of a
 * 950-line component. The state still lives in App because the flows share it
 * (a password typed on the auth screen is reused to complete OAuth), so this is
 * a presentational split rather than a change in ownership.
 */
export function AuthViews({
  view,
  isRegister,
  setIsRegister,
  email,
  setEmail,
  password,
  setPassword,
  name,
  setName,
  busy,
  totpCode,
  setTotpCode,
  recoveryCodeInput,
  setRecoveryCodeInput,
  handleAuth,
  handleUnlock,
  handleMfa,
  handleOAuth,
  handleOAuthComplete,
  handleForgot,
  handleReset,
  setView,
}: AuthViewsProps) {
  return (
    <>
      {view === 'auth' && (
        <AuthLayout>
          <AuthScreen
            isRegister={isRegister}
            setIsRegister={setIsRegister}
            email={email}
            setEmail={setEmail}
            password={password}
            setPassword={setPassword}
            name={name}
            setName={setName}
            onSubmit={handleAuth}
            onOAuth={handleOAuth}
            onForgot={() => setView('forgot')}
            busy={busy}
          />
        </AuthLayout>
      )}

      {view === 'unlock' && (
        <AuthLayout>
          <Card className="w-full max-w-sm p-8 shadow-lg">
            <div className="mb-6 text-center">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-primary-100 text-primary-600 dark:bg-primary-900/30">
                <Lock size={24} />
              </div>
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
                Unlock your vault
              </h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Your session is still active — enter your master password to
                decrypt your keys.
              </p>
            </div>
            <form onSubmit={handleUnlock} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
                  Master password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoFocus
                  disabled={!!busy}
                  placeholder="••••••••••••"
                  className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/30 disabled:opacity-60 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                />
              </div>
              <Button type="submit" className="w-full" disabled={!!busy}>
                {busy ? (
                  <span className="inline-flex items-center gap-2">
                    <Loader2 className="animate-spin" size={16} />
                    {busy}
                  </span>
                ) : (
                  'Unlock'
                )}
              </Button>
            </form>
            <div className="mt-4 text-center text-sm">
              <button
                type="button"
                onClick={() => {
                  clearPendingToken();
                  setView('auth');
                }}
                className="text-slate-500 underline-offset-2 hover:text-slate-700 hover:underline dark:text-slate-400 dark:hover:text-slate-200"
              >
                Sign in as a different user
              </button>
            </div>
          </Card>
        </AuthLayout>
      )}

      {view === 'mfa' && (
        <AuthLayout>
          <Card className="w-full max-w-sm p-8 shadow-lg">
            <div className="mb-6 text-center">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-primary-100 text-primary-600 dark:bg-primary-900/30">
                <Shield size={24} />
              </div>
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
                Two-factor authentication
              </h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Enter the code from your authenticator app.
              </p>
            </div>
            <form onSubmit={handleMfa} className="space-y-4">
              <div>
                <Label htmlFor="totp-code">Authenticator code</Label>
                <Input
                  id="totp-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  required
                />
              </div>
              <Button type="submit" className="w-full" disabled={Boolean(busy)}>
                {busy || 'Verify'}
              </Button>
            </form>
          </Card>
        </AuthLayout>
      )}

      {view === 'oauth' && (
        <AuthLayout>
          <Card className="w-full max-w-sm p-8 shadow-lg">
            <div className="mb-6 text-center">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-primary-100 text-primary-600 dark:bg-primary-900/30">
                <KeyRound size={24} />
              </div>
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
                Unlock your vault
              </h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                {isRegister
                  ? 'Set a master password to encrypt your keys.'
                  : 'Enter your master password to decrypt your keys.'}
              </p>
            </div>
            <form onSubmit={handleOAuthComplete} className="space-y-4">
              <div>
                <Label htmlFor="oauth-password">Master password</Label>
                <Input
                  id="oauth-password"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </div>
              <Button type="submit" className="w-full" disabled={Boolean(busy)}>
                {busy || 'Continue'}
              </Button>
            </form>
          </Card>
        </AuthLayout>
      )}

      {view === 'forgot' && (
        <AuthLayout>
          <Card className="w-full max-w-sm p-8 shadow-lg">
            <div className="mb-6 text-center">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-primary-100 text-primary-600 dark:bg-primary-900/30">
                <Mail size={24} />
              </div>
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Reset password</h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                We will email you a reset link.
              </p>
            </div>
            <form onSubmit={handleForgot} className="space-y-4">
              <div>
                <Label htmlFor="reset-email">Email</Label>
                <Input
                  id="reset-email"
                  type="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <Button type="submit" className="w-full" disabled={Boolean(busy)}>
                {busy || 'Send reset link'}
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={() => setView('auth')}
              >
                Back to sign in
              </Button>
            </form>
          </Card>
        </AuthLayout>
      )}

      {view === 'reset' && (
        <AuthLayout>
          <Card className="w-full max-w-sm p-8 shadow-lg">
            <div className="mb-6 text-center">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-primary-100 text-primary-600 dark:bg-primary-900/30">
                <KeyRound size={24} />
              </div>
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white">New password</h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Enter your recovery code and a new password.
              </p>
            </div>
            <form onSubmit={handleReset} className="space-y-4">
              <div>
                <Label htmlFor="recovery-code">Recovery code</Label>
                <Input
                  id="recovery-code"
                  type="text"
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  value={recoveryCodeInput}
                  onChange={(e) => setRecoveryCodeInput(e.target.value)}
                  required
                />
              </div>
              <div>
                <Label htmlFor="new-password">New password</Label>
                <Input
                  id="new-password"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </div>
              <Button type="submit" className="w-full" disabled={Boolean(busy)}>
                {busy || 'Reset password'}
              </Button>
            </form>
          </Card>
        </AuthLayout>
      )}
    </>
  );
}
