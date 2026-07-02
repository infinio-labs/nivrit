import { useEffect, useState, type ReactNode } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  KeyRound,
  Layers,
  LayoutDashboard,
  Loader2,
  LogOut,
  Mail,
  Plus,
  Settings,
  Shield,
  Trash2,
  Users,
} from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { initCrypto } from './crypto';
import { oauthAuthorizeUrl } from './api';
import {
  clearSession,
  createEnvironmentSession,
  createOrgSession,
  createProjectSession,
  deleteEncryptedSecret,
  disableTotpSession,
  forgotPasswordSession,
  getMyOrgsSession,
  getProjectEnvironments,
  getSession,
  inviteProjectMember,
  listEncryptedSecrets,
  listOrgProjectsSession,
  loginSession,
  loginTotpSession,
  processOAuthCallback,
  registerSession,
  resetPasswordSession,
  setEncryptedSecret,
  setupTotpSession,
  verifyTotpSession,
  type SecretEntry,
  type Session,
} from './session';
import { Button, Card, CardTitle, Input, Label, Select } from './components/ui';
import { ToastContainer, type ToastMessage } from './components/Toast';

interface Org {
  id: string;
  name: string;
  slug: string;
}

interface Project {
  id: string;
  org_id: string;
  name: string;
  slug: string;
}

interface Environment {
  id: string;
  project_id: string;
  name: string;
  slug: string;
}

type View =
  | 'auth'
  | 'mfa'
  | 'oauth'
  | 'forgot'
  | 'reset'
  | 'dashboard';

type Tab = 'secrets' | 'members' | 'settings';

function App() {
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<View>('auth');
  const [session, setSession] = useState<Session | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // Auth form state
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');

  // MFA
  const [tempToken, setTempToken] = useState('');
  const [mfaPassword, setMfaPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');

  // OAuth / reset
  const [oauthProvider, setOauthProvider] = useState('');
  const [oauthCode, setOauthCode] = useState('');
  const [oauthState, setOauthState] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [recoveryCodeInput, setRecoveryCodeInput] = useState('');

  // Dashboard state
  const [activeTab, setActiveTab] = useState<Tab>('secrets');
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState('');
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState('');
  const [secrets, setSecrets] = useState<SecretEntry[]>([]);
  const [listing, setListing] = useState(false);
  const [secretKey, setSecretKey] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'member' | 'viewer'>('member');

  // Create form state
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgSlug, setNewOrgSlug] = useState('');
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectSlug, setNewProjectSlug] = useState('');
  const [newEnvName, setNewEnvName] = useState('');
  const [newEnvSlug, setNewEnvSlug] = useState('');

  // Settings / TOTP
  const [totpSecret, setTotpSecret] = useState('');
  const [totpUri, setTotpUri] = useState('');
  const [totpVerifyCode, setTotpVerifyCode] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [disableTotpPassword, setDisableTotpPassword] = useState('');
  const [disableTotpCode, setDisableTotpCode] = useState('');

  useEffect(() => {
    initCrypto()
      .then(() => {
        // Purge any token left in localStorage by older builds; sessions are
        // in-memory only now.
        localStorage.removeItem('nivrit_token');
        setLoading(false);
        detectOAuthCallback();
        detectResetToken();
      })
      .catch((e) => {
        showToast(`failed to initialize crypto: ${e}`, 'error');
        setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    getMyOrgsSession()
      .then((items) => {
        if (cancelled) return;
        setOrgs(items);
      })
      .catch(() => setOrgs([]));
    return () => {
      cancelled = true;
    };
  }, [session]);

  useEffect(() => {
    if (!selectedOrgId) {
      setProjects([]);
      setSelectedProjectId('');
      return;
    }
    let cancelled = false;
    listOrgProjectsSession(selectedOrgId)
      .then((items) => {
        if (cancelled) return;
        setProjects(items);
      })
      .catch(() => setProjects([]));
    return () => {
      cancelled = true;
    };
  }, [selectedOrgId]);

  useEffect(() => {
    if (!selectedProjectId) {
      setEnvironments([]);
      setSelectedEnvironmentId('');
      setSecrets([]);
      return;
    }
    let cancelled = false;
    getProjectEnvironments(selectedProjectId)
      .then((items) => {
        if (cancelled) return;
        setEnvironments(items);
        if (items.length > 0 && !selectedEnvironmentId) {
          setSelectedEnvironmentId(items[0].id);
        }
      })
      .catch(() => setEnvironments([]));
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId]);

  useEffect(() => {
    if (!selectedProjectId || !selectedEnvironmentId) {
      setSecrets([]);
      return;
    }
    let cancelled = false;
    setListing(true);
    listEncryptedSecrets(selectedProjectId, selectedEnvironmentId)
      .then((items) => {
        if (cancelled) return;
        setSecrets(items);
      })
      .catch(() => setSecrets([]))
      .finally(() => setListing(false));
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId, selectedEnvironmentId]);

  function detectOAuthCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const provider = params.get('provider');
    const state = params.get('state');
    if (code && provider && state) {
      setOauthProvider(provider);
      setOauthCode(code);
      setOauthState(state);
      setView('oauth');
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }

  function detectResetToken() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    if (token) {
      setResetToken(token);
      setView('reset');
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }

  function showToast(message: string, type: 'success' | 'error') {
    const id = Math.random().toString(36).slice(2);
    setToasts((prev) => [...prev, { id, message, type }]);
  }

  function dismissToast(id: string) {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  async function handleAuth(e: React.FormEvent) {
    e.preventDefault();
    try {
      if (isRegister) {
        const { recoveryCode: rc } = await registerSession(email, password, name || undefined);
        setRecoveryCode(rc);
      } else {
        const result = await loginSession(email, password);
        if (result.status === 'MfaRequired') {
          setTempToken(result.temp_token);
          setMfaPassword(password);
          setView('mfa');
          return;
        }
      }
      setSession(getSession());
      setView('dashboard');
    } catch (err) {
      showToast(isRegister ? 'registration failed' : 'login failed', 'error');
    }
  }

  async function handleMfa(e: React.FormEvent) {
    e.preventDefault();
    try {
      await loginTotpSession(tempToken, totpCode, mfaPassword);
      setSession(getSession());
      setView('dashboard');
    } catch {
      showToast('invalid TOTP code', 'error');
    }
  }

  async function handleOAuth(provider: 'google' | 'github') {
    try {
      const { url } = await oauthAuthorizeUrl(provider);
      window.location.href = url;
    } catch {
      showToast('OAuth authorization failed', 'error');
    }
  }

  async function handleOAuthComplete(e: React.FormEvent) {
    e.preventDefault();
    try {
      const { recoveryCode: rc } = await processOAuthCallback(
        oauthProvider,
        oauthCode,
        oauthState,
        password
      );
      if (rc) setRecoveryCode(rc);
      setSession(getSession());
      setView('dashboard');
    } catch {
      showToast('OAuth login failed', 'error');
    }
  }

  async function handleForgot(e: React.FormEvent) {
    e.preventDefault();
    try {
      await forgotPasswordSession(email);
      showToast('If this email exists, a reset link has been sent.', 'success');
      setView('auth');
    } catch {
      showToast('failed to send reset email', 'error');
    }
  }

  async function handleReset(e: React.FormEvent) {
    e.preventDefault();
    try {
      await resetPasswordSession(resetToken, recoveryCodeInput, password);
      setSession(getSession());
      setView('dashboard');
      showToast('password reset successfully', 'success');
    } catch {
      showToast('password reset failed', 'error');
    }
  }

  function handleLogout() {
    clearSession();
    setSession(null);
    resetDashboard();
    setView('auth');
  }

  function resetDashboard() {
    setSelectedOrgId('');
    setSelectedProjectId('');
    setSelectedEnvironmentId('');
    setOrgs([]);
    setProjects([]);
    setEnvironments([]);
    setSecrets([]);
    setActiveTab('secrets');
  }

  async function refreshSecrets() {
    if (!selectedProjectId || !selectedEnvironmentId) return;
    setListing(true);
    try {
      const items = await listEncryptedSecrets(selectedProjectId, selectedEnvironmentId);
      setSecrets(items);
    } catch (e) {
      console.warn('failed to refresh secrets', e);
    } finally {
      setListing(false);
    }
  }

  async function handleSetSecret(e: React.FormEvent) {
    e.preventDefault();
    try {
      await setEncryptedSecret(selectedProjectId, selectedEnvironmentId, secretKey, secretValue);
      setSecretValue('');
      await refreshSecrets();
      showToast('secret saved', 'success');
    } catch {
      showToast('failed to save secret', 'error');
    }
  }

  async function handleDeleteSecret(key: string) {
    if (!confirm(`Delete secret "${key}"?`)) return;
    try {
      await deleteEncryptedSecret(selectedProjectId, selectedEnvironmentId, key);
      await refreshSecrets();
      showToast('secret deleted', 'success');
    } catch {
      showToast('failed to delete secret', 'error');
    }
  }

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    try {
      await inviteProjectMember(selectedProjectId, inviteEmail, inviteRole);
      setInviteEmail('');
      showToast(`invited ${inviteEmail}`, 'success');
    } catch {
      showToast('invite failed', 'error');
    }
  }

  async function handleCreateOrg(e: React.FormEvent) {
    e.preventDefault();
    try {
      const org = await createOrgSession(newOrgName, newOrgSlug);
      setOrgs((prev) => [...prev, org]);
      setSelectedOrgId(org.id);
      setNewOrgName('');
      setNewOrgSlug('');
      showToast(`created organization ${org.name}`, 'success');
    } catch {
      showToast('failed to create organization', 'error');
    }
  }

  async function handleCreateProject(e: React.FormEvent) {
    e.preventDefault();
    try {
      const project = await createProjectSession(selectedOrgId, newProjectName, newProjectSlug);
      setProjects((prev) => [...prev, project]);
      setSelectedProjectId(project.id);
      setNewProjectName('');
      setNewProjectSlug('');
      showToast(`created project ${project.name}`, 'success');
    } catch {
      showToast('failed to create project', 'error');
    }
  }

  async function handleCreateEnvironment(e: React.FormEvent) {
    e.preventDefault();
    try {
      const env = await createEnvironmentSession(selectedProjectId, newEnvName, newEnvSlug);
      setEnvironments((prev) => [...prev, env]);
      setSelectedEnvironmentId(env.id);
      setNewEnvName('');
      setNewEnvSlug('');
      showToast(`created environment ${env.name}`, 'success');
    } catch {
      showToast('failed to create environment', 'error');
    }
  }

  async function handleSetupTotp() {
    const s = getSession();
    if (!s) return;
    try {
      const res = await setupTotpSession(s.token);
      setTotpSecret(res.secret);
      setTotpUri(res.uri);
    } catch {
      showToast('failed to setup 2FA', 'error');
    }
  }

  async function handleVerifyTotp(e: React.FormEvent) {
    e.preventDefault();
    const s = getSession();
    if (!s) return;
    try {
      await verifyTotpSession(s.token, totpVerifyCode);
      setTotpEnabled(true);
      setTotpSecret('');
      setTotpUri('');
      setTotpVerifyCode('');
      showToast('2FA enabled', 'success');
    } catch {
      showToast('invalid TOTP code', 'error');
    }
  }

  async function handleDisableTotp(e: React.FormEvent) {
    e.preventDefault();
    const s = getSession();
    if (!s) return;
    try {
      await disableTotpSession(s.token, disableTotpPassword, disableTotpCode);
      setTotpEnabled(false);
      setDisableTotpPassword('');
      setDisableTotpCode('');
      showToast('2FA disabled', 'success');
    } catch {
      showToast('failed to disable 2FA', 'error');
    }
  }

  const hasProjectKey = session ? session.projects.has(selectedProjectId) : false;

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loader2 className="animate-spin text-primary-600" size={32} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      {view === 'auth' && (
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
        />
      )}

      {view === 'mfa' && (
        <div className="flex h-screen items-center justify-center p-4">
          <Card className="w-full max-w-sm p-8">
            <div className="mb-6 text-center">
              <Shield className="mx-auto mb-3 text-primary-600" size={40} />
              <h1 className="text-2xl font-bold">Two-factor authentication</h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">Enter the code from your authenticator app.</p>
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
              <Button type="submit" className="w-full">Verify</Button>
            </form>
          </Card>
        </div>
      )}

      {view === 'oauth' && (
        <div className="flex h-screen items-center justify-center p-4">
          <Card className="w-full max-w-sm p-8">
            <div className="mb-6 text-center">
              <KeyRound className="mx-auto mb-3 text-primary-600" size={40} />
              <h1 className="text-2xl font-bold">Unlock your vault</h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                {isRegister ? 'Set a master password to encrypt your keys.' : 'Enter your master password to decrypt your keys.'}
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
              <Button type="submit" className="w-full">Continue</Button>
            </form>
          </Card>
        </div>
      )}

      {view === 'forgot' && (
        <div className="flex h-screen items-center justify-center p-4">
          <Card className="w-full max-w-sm p-8">
            <div className="mb-6 text-center">
              <Mail className="mx-auto mb-3 text-primary-600" size={40} />
              <h1 className="text-2xl font-bold">Reset password</h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">We will email you a reset link.</p>
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
              <Button type="submit" className="w-full">Send reset link</Button>
              <Button type="button" variant="ghost" className="w-full" onClick={() => setView('auth')}>
                Back to sign in
              </Button>
            </form>
          </Card>
        </div>
      )}

      {view === 'reset' && (
        <div className="flex h-screen items-center justify-center p-4">
          <Card className="w-full max-w-sm p-8">
            <div className="mb-6 text-center">
              <KeyRound className="mx-auto mb-3 text-primary-600" size={40} />
              <h1 className="text-2xl font-bold">New password</h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">Enter your recovery code and a new password.</p>
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
              <Button type="submit" className="w-full">Reset password</Button>
            </form>
          </Card>
        </div>
      )}

      {view === 'dashboard' && session && (
        <Dashboard
          session={session}
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          orgs={orgs}
          selectedOrgId={selectedOrgId}
          setSelectedOrgId={setSelectedOrgId}
          projects={projects}
          selectedProjectId={selectedProjectId}
          setSelectedProjectId={setSelectedProjectId}
          environments={environments}
          selectedEnvironmentId={selectedEnvironmentId}
          setSelectedEnvironmentId={setSelectedEnvironmentId}
          secrets={secrets}
          listing={listing}
          secretKey={secretKey}
          setSecretKey={setSecretKey}
          secretValue={secretValue}
          setSecretValue={setSecretValue}
          onSetSecret={handleSetSecret}
          onDeleteSecret={handleDeleteSecret}
          inviteEmail={inviteEmail}
          setInviteEmail={setInviteEmail}
          inviteRole={inviteRole}
          setInviteRole={setInviteRole}
          onInvite={handleInvite}
          newOrgName={newOrgName}
          setNewOrgName={setNewOrgName}
          newOrgSlug={newOrgSlug}
          setNewOrgSlug={setNewOrgSlug}
          onCreateOrg={handleCreateOrg}
          newProjectName={newProjectName}
          setNewProjectName={setNewProjectName}
          newProjectSlug={newProjectSlug}
          setNewProjectSlug={setNewProjectSlug}
          onCreateProject={handleCreateProject}
          newEnvName={newEnvName}
          setNewEnvName={setNewEnvName}
          newEnvSlug={newEnvSlug}
          setNewEnvSlug={setNewEnvSlug}
          onCreateEnvironment={handleCreateEnvironment}
          hasProjectKey={hasProjectKey}
          onLogout={handleLogout}
          totpEnabled={totpEnabled}
          totpSecret={totpSecret}
          totpUri={totpUri}
          totpVerifyCode={totpVerifyCode}
          setTotpVerifyCode={setTotpVerifyCode}
          onSetupTotp={handleSetupTotp}
          onVerifyTotp={handleVerifyTotp}
          disableTotpPassword={disableTotpPassword}
          setDisableTotpPassword={setDisableTotpPassword}
          disableTotpCode={disableTotpCode}
          setDisableTotpCode={setDisableTotpCode}
          onDisableTotp={handleDisableTotp}
        />
      )}

      {recoveryCode && (
        <RecoveryCodeModal
          code={recoveryCode}
          onClose={() => setRecoveryCode('')}
        />
      )}

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Auth screen
// ---------------------------------------------------------------------------

function AuthScreen({
  isRegister,
  setIsRegister,
  email,
  setEmail,
  password,
  setPassword,
  name,
  setName,
  onSubmit,
  onOAuth,
  onForgot,
}: {
  isRegister: boolean;
  setIsRegister: (v: boolean) => void;
  email: string;
  setEmail: (v: string) => void;
  password: string;
  setPassword: (v: string) => void;
  name: string;
  setName: (v: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  onOAuth: (p: 'google' | 'github') => void;
  onForgot: () => void;
}) {
  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md p-8">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-primary-600 text-white">
            <Shield size={24} />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Nivrit</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">End-to-end encrypted secrets management</p>
        </div>

        <div className="mb-6 flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800">
          <button
            type="button"
            onClick={() => setIsRegister(false)}
            className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
              !isRegister ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-white' : 'text-slate-500 dark:text-slate-400'
            }`}
          >
            Sign in
          </button>
          <button
            type="button"
            onClick={() => setIsRegister(true)}
            className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
              isRegister ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-white' : 'text-slate-500 dark:text-slate-400'
            }`}
          >
            Create account
          </button>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              data-testid="email-input"
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div>
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              data-testid="password-input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
            />
          </div>
          {isRegister && (
            <div>
              <Label htmlFor="name">Name (optional)</Label>
              <Input
                id="name"
                type="text"
                placeholder="Jane Doe"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
          )}
          <Button type="submit" data-testid="auth-submit" className="w-full">
            {isRegister ? 'Create account' : 'Sign in'}
          </Button>
        </form>

        {!isRegister && (
          <div className="mt-4 text-center">
            <button type="button" onClick={onForgot} className="text-sm text-primary-600 hover:underline dark:text-primary-400">
              Forgot password?
            </button>
          </div>
        )}

        <div className="my-6 flex items-center gap-3">
          <div className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />
          <span className="text-xs font-medium uppercase text-slate-400">or continue with</span>
          <div className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Button type="button" variant="secondary" onClick={() => onOAuth('google')}>
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
              <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
              <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
            </svg>
            Google
          </Button>
          <Button type="button" variant="secondary" onClick={() => onOAuth('github')}>
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.419-1.305.762-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
            </svg>
            GitHub
          </Button>
        </div>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Recovery code modal
// ---------------------------------------------------------------------------

function RecoveryCodeModal({ code, onClose }: { code: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4">
      <Card className="w-full max-w-md p-6">
        <div className="mb-4 flex items-start gap-3">
          <AlertTriangle className="text-amber-500" size={24} />
          <div>
            <h2 className="text-lg font-semibold">Save your recovery code</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              This is the only way to reset your password. We cannot recover it for you.
            </p>
          </div>
        </div>
        <div className="mb-4 flex items-center justify-between rounded-lg bg-slate-100 p-4 dark:bg-slate-800">
          <code className="text-sm font-bold tracking-wider">{code}</code>
          <button
            type="button"
            onClick={() => {
              navigator.clipboard.writeText(code);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
            className="text-slate-500 hover:text-slate-900 dark:hover:text-slate-100"
          >
            {copied ? <Check size={18} /> : <Copy size={18} />}
          </button>
        </div>
        <Button onClick={onClose} className="w-full">
          I have saved it
        </Button>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

function Dashboard(props: {
  session: Session;
  activeTab: Tab;
  setActiveTab: (t: Tab) => void;
  orgs: Org[];
  selectedOrgId: string;
  setSelectedOrgId: (id: string) => void;
  projects: Project[];
  selectedProjectId: string;
  setSelectedProjectId: (id: string) => void;
  environments: Environment[];
  selectedEnvironmentId: string;
  setSelectedEnvironmentId: (id: string) => void;
  secrets: SecretEntry[];
  listing: boolean;
  secretKey: string;
  setSecretKey: (v: string) => void;
  secretValue: string;
  setSecretValue: (v: string) => void;
  onSetSecret: (e: React.FormEvent) => void;
  onDeleteSecret: (key: string) => void;
  inviteEmail: string;
  setInviteEmail: (v: string) => void;
  inviteRole: 'admin' | 'member' | 'viewer';
  setInviteRole: (v: 'admin' | 'member' | 'viewer') => void;
  onInvite: (e: React.FormEvent) => void;
  newOrgName: string;
  setNewOrgName: (v: string) => void;
  newOrgSlug: string;
  setNewOrgSlug: (v: string) => void;
  onCreateOrg: (e: React.FormEvent) => void;
  newProjectName: string;
  setNewProjectName: (v: string) => void;
  newProjectSlug: string;
  setNewProjectSlug: (v: string) => void;
  onCreateProject: (e: React.FormEvent) => void;
  newEnvName: string;
  setNewEnvName: (v: string) => void;
  newEnvSlug: string;
  setNewEnvSlug: (v: string) => void;
  onCreateEnvironment: (e: React.FormEvent) => void;
  hasProjectKey: boolean;
  onLogout: () => void;
  totpEnabled: boolean;
  totpSecret: string;
  totpUri: string;
  totpVerifyCode: string;
  setTotpVerifyCode: (v: string) => void;
  onSetupTotp: () => void;
  onVerifyTotp: (e: React.FormEvent) => void;
  disableTotpPassword: string;
  setDisableTotpPassword: (v: string) => void;
  disableTotpCode: string;
  setDisableTotpCode: (v: string) => void;
  onDisableTotp: (e: React.FormEvent) => void;
}) {
  const navItems: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: 'secrets', label: 'Secrets', icon: LayoutDashboard },
    { id: 'members', label: 'Members', icon: Users },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="hidden w-56 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 md:flex">
        <div className="flex items-center gap-2 px-5 py-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary-600 text-white">
            <Shield size={18} />
          </div>
          <span className="text-lg font-bold">Nivrit</span>
        </div>
        <nav className="flex-1 px-3 py-4">
          {navItems.map((item) => {
            const active = props.activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => props.setActiveTab(item.id)}
                className={`mb-1 flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  active
                    ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'
                    : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
                }`}
              >
                <item.icon size={18} />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="border-t border-slate-200 p-4 dark:border-slate-800">
          <div className="mb-3 truncate text-xs font-medium text-slate-500 dark:text-slate-400">
            {props.session.email}
          </div>
          <Button variant="ghost" className="w-full justify-start" onClick={props.onLogout}>
            <LogOut size={16} />
            Sign out
          </Button>
        </div>
      </aside>

      <div className="flex flex-1 flex-col">
        {/* Topbar */}
        <header className="sticky top-0 z-10 flex flex-wrap items-center gap-4 border-b border-slate-200 bg-white/80 px-4 py-3 backdrop-blur dark:border-slate-800 dark:bg-slate-900/80 md:px-6">
          <div className="flex items-center gap-2 md:hidden">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary-600 text-white">
              <Shield size={18} />
            </div>
            <span className="font-bold">Nivrit</span>
          </div>

          <div className="flex flex-1 flex-wrap items-center gap-3">
            <ContextSelect
              label="Organization"
              value={props.selectedOrgId}
              onChange={props.setSelectedOrgId}
              options={props.orgs.map((o) => ({ value: o.id, label: o.name || o.slug }))}
              placeholder="Select organization"
              testId="org-select"
            />
            <ContextSelect
              label="Project"
              value={props.selectedProjectId}
              onChange={props.setSelectedProjectId}
              options={props.projects.map((p) => ({ value: p.id, label: p.name || p.slug }))}
              placeholder="Select project"
              disabled={!props.selectedOrgId}
              testId="project-select"
            />
            <ContextSelect
              label="Environment"
              value={props.selectedEnvironmentId}
              onChange={props.setSelectedEnvironmentId}
              options={props.environments.map((e) => ({ value: e.id, label: e.name || e.slug }))}
              placeholder="Select environment"
              disabled={!props.selectedProjectId}
              testId="env-select"
            />
          </div>

          <div className="hidden items-center gap-3 md:flex">
            <span className="text-sm text-slate-500 dark:text-slate-400">{props.session.email}</span>
            <Button variant="ghost" onClick={props.onLogout}>
              <LogOut size={16} />
            </Button>
          </div>
        </header>

        {/* Main */}
        <main className="flex-1 p-4 md:p-6">
          {props.activeTab === 'secrets' && (
            <SecretsTab
              orgs={props.orgs}
              selectedOrgId={props.selectedOrgId}
              setSelectedOrgId={props.setSelectedOrgId}
              projects={props.projects}
              selectedProjectId={props.selectedProjectId}
              setSelectedProjectId={props.setSelectedProjectId}
              environments={props.environments}
              selectedEnvironmentId={props.selectedEnvironmentId}
              setSelectedEnvironmentId={props.setSelectedEnvironmentId}
              secrets={props.secrets}
              listing={props.listing}
              secretKey={props.secretKey}
              setSecretKey={props.setSecretKey}
              secretValue={props.secretValue}
              setSecretValue={props.setSecretValue}
              onSetSecret={props.onSetSecret}
              onDeleteSecret={props.onDeleteSecret}
              newOrgName={props.newOrgName}
              setNewOrgName={props.setNewOrgName}
              newOrgSlug={props.newOrgSlug}
              setNewOrgSlug={props.setNewOrgSlug}
              onCreateOrg={props.onCreateOrg}
              newProjectName={props.newProjectName}
              setNewProjectName={props.setNewProjectName}
              newProjectSlug={props.newProjectSlug}
              setNewProjectSlug={props.setNewProjectSlug}
              onCreateProject={props.onCreateProject}
              newEnvName={props.newEnvName}
              setNewEnvName={props.setNewEnvName}
              newEnvSlug={props.newEnvSlug}
              setNewEnvSlug={props.setNewEnvSlug}
              onCreateEnvironment={props.onCreateEnvironment}
              hasProjectKey={props.hasProjectKey}
            />
          )}
          {props.activeTab === 'members' && (
            <MembersTab
              selectedProjectId={props.selectedProjectId}
              inviteEmail={props.inviteEmail}
              setInviteEmail={props.setInviteEmail}
              inviteRole={props.inviteRole}
              setInviteRole={props.setInviteRole}
              onInvite={props.onInvite}
            />
          )}
          {props.activeTab === 'settings' && (
            <SettingsTab
              totpEnabled={props.totpEnabled}
              totpSecret={props.totpSecret}
              totpUri={props.totpUri}
              totpVerifyCode={props.totpVerifyCode}
              setTotpVerifyCode={props.setTotpVerifyCode}
              onSetupTotp={props.onSetupTotp}
              onVerifyTotp={props.onVerifyTotp}
              disableTotpPassword={props.disableTotpPassword}
              setDisableTotpPassword={props.setDisableTotpPassword}
              disableTotpCode={props.disableTotpCode}
              setDisableTotpCode={props.setDisableTotpCode}
              onDisableTotp={props.onDisableTotp}
            />
          )}
        </main>
      </div>
    </div>
  );
}

function ContextSelect({
  label,
  value,
  onChange,
  options,
  placeholder,
  disabled,
  testId,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  placeholder: string;
  disabled?: boolean;
  testId: string;
}) {
  return (
    <div className="min-w-[180px] flex-1">
      <Label>{label}</Label>
      <Select data-testid={testId} value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled}>
        <option value="">{placeholder}</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Secrets tab
// ---------------------------------------------------------------------------

function SecretsTab(props: {
  orgs: Org[];
  selectedOrgId: string;
  setSelectedOrgId: (id: string) => void;
  projects: Project[];
  selectedProjectId: string;
  setSelectedProjectId: (id: string) => void;
  environments: Environment[];
  selectedEnvironmentId: string;
  setSelectedEnvironmentId: (id: string) => void;
  secrets: SecretEntry[];
  listing: boolean;
  secretKey: string;
  setSecretKey: (v: string) => void;
  secretValue: string;
  setSecretValue: (v: string) => void;
  onSetSecret: (e: React.FormEvent) => void;
  onDeleteSecret: (key: string) => void;
  newOrgName: string;
  setNewOrgName: (v: string) => void;
  newOrgSlug: string;
  setNewOrgSlug: (v: string) => void;
  onCreateOrg: (e: React.FormEvent) => void;
  newProjectName: string;
  setNewProjectName: (v: string) => void;
  newProjectSlug: string;
  setNewProjectSlug: (v: string) => void;
  onCreateProject: (e: React.FormEvent) => void;
  newEnvName: string;
  setNewEnvName: (v: string) => void;
  newEnvSlug: string;
  setNewEnvSlug: (v: string) => void;
  onCreateEnvironment: (e: React.FormEvent) => void;
  hasProjectKey: boolean;
}) {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-3">
        <CreateCard title="Create organization" onSubmit={props.onCreateOrg}>
          <Input data-testid="org-name-input" placeholder="Organization name" value={props.newOrgName} onChange={(e) => props.setNewOrgName(e.target.value)} required />
          <Input data-testid="org-slug-input" placeholder="org-slug" value={props.newOrgSlug} onChange={(e) => props.setNewOrgSlug(e.target.value)} required />
          <Button type="submit" data-testid="create-org-btn">Create org</Button>
        </CreateCard>

        {props.selectedOrgId && (
          <CreateCard title="Create project" onSubmit={props.onCreateProject}>
            <Input data-testid="project-name-input" placeholder="Project name" value={props.newProjectName} onChange={(e) => props.setNewProjectName(e.target.value)} required />
            <Input data-testid="project-slug-input" placeholder="project-slug" value={props.newProjectSlug} onChange={(e) => props.setNewProjectSlug(e.target.value)} required />
            <Button type="submit" data-testid="create-project-btn">Create project</Button>
          </CreateCard>
        )}

        {props.selectedProjectId && (
          <CreateCard title="Create environment" onSubmit={props.onCreateEnvironment}>
            <Input data-testid="env-name-input" placeholder="Environment name" value={props.newEnvName} onChange={(e) => props.setNewEnvName(e.target.value)} required />
            <Input data-testid="env-slug-input" placeholder="env-slug" value={props.newEnvSlug} onChange={(e) => props.setNewEnvSlug(e.target.value)} required />
            <Button type="submit" data-testid="create-env-btn">Create environment</Button>
          </CreateCard>
        )}
      </div>

      {props.selectedProjectId && !props.hasProjectKey && (
        <Card className="flex items-center gap-3 border-amber-200 bg-amber-50 p-4 dark:border-amber-900/50 dark:bg-amber-900/20">
          <AlertTriangle className="text-amber-600 dark:text-amber-400" size={20} />
          <p className="text-sm text-amber-800 dark:text-amber-200">
            Project key not available. You may need to be invited to this project.
          </p>
        </Card>
      )}

      {props.selectedProjectId && props.selectedEnvironmentId && props.hasProjectKey && (
        <Card className="p-5">
          <CardTitle className="mb-4">Secrets</CardTitle>
          <form onSubmit={props.onSetSecret} className="mb-6 flex flex-wrap gap-3">
            <Input
              data-testid="secret-key-input"
              placeholder="Secret key"
              value={props.secretKey}
              onChange={(e) => props.setSecretKey(e.target.value)}
              required
              className="min-w-[200px] flex-1"
            />
            <Input
              data-testid="secret-value-input"
              placeholder="Secret value"
              value={props.secretValue}
              onChange={(e) => props.setSecretValue(e.target.value)}
              required
              className="min-w-[200px] flex-1"
            />
            <Button type="submit" data-testid="set-secret-btn">
              <Plus size={16} />
              Add secret
            </Button>
          </form>

          {props.listing ? (
            <div className="flex items-center gap-2 text-sm text-slate-500">
              <Loader2 className="animate-spin" size={16} />
              Loading secrets…
            </div>
          ) : props.secrets.length === 0 ? (
            <p className="text-sm text-slate-500 dark:text-slate-400">No secrets in this environment.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-200 dark:border-slate-700">
                  <tr>
                    <th className="pb-2 font-medium text-slate-500 dark:text-slate-400">Key</th>
                    <th className="pb-2 font-medium text-slate-500 dark:text-slate-400">Value</th>
                    <th className="pb-2 font-medium text-slate-500 dark:text-slate-400">Version</th>
                    <th className="pb-2"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {props.secrets.map((s) => (
                    <SecretRow key={s.id} secret={s} onDelete={props.onDeleteSecret} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function CreateCard({ title, children, onSubmit }: { title: string; children: ReactNode; onSubmit: (e: React.FormEvent) => void }) {
  return (
    <Card className="p-5">
      <CardTitle className="mb-4">{title}</CardTitle>
      <form onSubmit={onSubmit} className="flex flex-wrap items-end gap-3">
        {children}
      </form>
    </Card>
  );
}

function SecretRow({ secret, onDelete }: { secret: SecretEntry; onDelete: (k: string) => void }) {
  const [revealed, setRevealed] = useState(false);
  return (
    <tr className="group">
      <td className="py-3 font-medium">{secret.key}</td>
      <td className="py-3 font-mono text-slate-600 dark:text-slate-300">
        {revealed ? secret.value : '•'.repeat(Math.min(secret.value.length, 12))}
      </td>
      <td className="py-3 text-slate-500">{secret.version}</td>
      <td className="py-3">
        <div className="flex items-center justify-end gap-2 opacity-80 group-hover:opacity-100">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setRevealed(!revealed)}
            title={revealed ? 'Hide' : 'Reveal'}
          >
            {revealed ? 'Hide' : 'Show'}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => navigator.clipboard.writeText(secret.value)}
            title="Copy"
          >
            <Copy size={16} />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => onDelete(secret.key)}
            title="Delete"
            className="text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20"
          >
            <Trash2 size={16} />
          </Button>
        </div>
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Members tab
// ---------------------------------------------------------------------------

function MembersTab(props: {
  selectedProjectId: string;
  inviteEmail: string;
  setInviteEmail: (v: string) => void;
  inviteRole: 'admin' | 'member' | 'viewer';
  setInviteRole: (v: 'admin' | 'member' | 'viewer') => void;
  onInvite: (e: React.FormEvent) => void;
}) {
  return (
    <Card className="max-w-xl p-5">
      <CardTitle className="mb-4">Invite member</CardTitle>
      {!props.selectedProjectId ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">Select a project first.</p>
      ) : (
        <form onSubmit={props.onInvite} className="space-y-4">
          <div>
            <Label htmlFor="invite-email">Email</Label>
            <Input
              id="invite-email"
              data-testid="invite-email-input"
              type="email"
              placeholder="teammate@example.com"
              value={props.inviteEmail}
              onChange={(e) => props.setInviteEmail(e.target.value)}
              required
            />
          </div>
          <div>
            <Label htmlFor="invite-role">Role</Label>
            <Select
              id="invite-role"
              data-testid="invite-role-select"
              value={props.inviteRole}
              onChange={(e) => props.setInviteRole(e.target.value as typeof props.inviteRole)}
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
              <option value="viewer">Viewer</option>
            </Select>
          </div>
          <Button type="submit" data-testid="invite-btn">Send invite</Button>
        </form>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Settings tab
// ---------------------------------------------------------------------------

function SettingsTab(props: {
  totpEnabled: boolean;
  totpSecret: string;
  totpUri: string;
  totpVerifyCode: string;
  setTotpVerifyCode: (v: string) => void;
  onSetupTotp: () => void;
  onVerifyTotp: (e: React.FormEvent) => void;
  disableTotpPassword: string;
  setDisableTotpPassword: (v: string) => void;
  disableTotpCode: string;
  setDisableTotpCode: (v: string) => void;
  onDisableTotp: (e: React.FormEvent) => void;
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="p-5">
        <CardTitle className="mb-4 flex items-center gap-2">
          <Shield size={16} />
          Two-factor authentication
        </CardTitle>
        {props.totpEnabled ? (
          <div>
            <p className="mb-4 text-sm text-green-700 dark:text-green-400">2FA is enabled.</p>
            <form onSubmit={props.onDisableTotp} className="space-y-4">
              <Input
                type="password"
                placeholder="Current password"
                value={props.disableTotpPassword}
                onChange={(e) => props.setDisableTotpPassword(e.target.value)}
                required
              />
              <Input
                type="text"
                inputMode="numeric"
                placeholder="TOTP code"
                value={props.disableTotpCode}
                onChange={(e) => props.setDisableTotpCode(e.target.value)}
                required
              />
              <Button type="submit" variant="secondary">Disable 2FA</Button>
            </form>
          </div>
        ) : (
          <div>
            <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">
              Add an extra layer of security with an authenticator app.
            </p>
            {!props.totpSecret ? (
              <Button onClick={props.onSetupTotp}>Setup 2FA</Button>
            ) : (
              <form onSubmit={props.onVerifyTotp} className="space-y-4">
                <div className="inline-block rounded-lg bg-white p-2 dark:bg-slate-800">
                  <QRCodeSVG value={props.totpUri} size={160} />
                </div>
                <div className="font-mono text-xs text-slate-600 dark:text-slate-300">{props.totpSecret}</div>
                <Input
                  type="text"
                  inputMode="numeric"
                  placeholder="Enter code from app"
                  value={props.totpVerifyCode}
                  onChange={(e) => props.setTotpVerifyCode(e.target.value)}
                  required
                />
                <Button type="submit">Enable 2FA</Button>
              </form>
            )}
          </div>
        )}
      </Card>

      <Card className="p-5">
        <CardTitle className="mb-4 flex items-center gap-2">
          <Layers size={16} />
          Recovery
        </CardTitle>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Your recovery code was shown when you created your account. Without it, password resets are impossible.
        </p>
      </Card>
    </div>
  );
}

export default App;
