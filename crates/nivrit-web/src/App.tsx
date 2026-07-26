import { useEffect, useState } from 'react';
import { KeyRound, Loader2, Mail, Shield } from './components/icons';
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
import { Button, Card, Input, Label } from './components/ui';
import { ToastContainer, type ToastMessage } from './components/Toast';
import { AuthLayout } from './components/AuthLayout';
import { AuthScreen } from './components/AuthScreen';
import { RecoveryCodeModal } from './components/RecoveryCodeModal';
import { ImportEnvModal } from './components/ImportEnvModal';
import { Dashboard } from './components/Dashboard';
import { SecretsTab } from './components/SecretsTab';
import { MembersTab } from './components/MembersTab';
import { SettingsTab } from './components/SettingsTab';

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

type View = 'auth' | 'mfa' | 'oauth' | 'forgot' | 'reset' | 'dashboard';
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
  const [editingSecretKey, setEditingSecretKey] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'member' | 'viewer'>('member');

  // Create form state
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgSlug, setNewOrgSlug] = useState('');
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectSlug, setNewProjectSlug] = useState('');
  const [newEnvName, setNewEnvName] = useState('');
  const [newEnvSlug, setNewEnvSlug] = useState('');

  // Import .env modal
  const [importOpen, setImportOpen] = useState(false);
  const [importContent, setImportContent] = useState('');
  const [importing, setImporting] = useState(false);

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
    } catch {
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
      setSecretKey('');
      setSecretValue('');
      setEditingSecretKey('');
      await refreshSecrets();
      showToast('secret saved', 'success');
    } catch {
      showToast('failed to save secret', 'error');
    }
  }

  function handleStartEdit(secret: SecretEntry) {
    setSecretKey(secret.key);
    setSecretValue(secret.value);
    setEditingSecretKey(secret.key);
  }

  function handleCancelEdit() {
    setSecretKey('');
    setSecretValue('');
    setEditingSecretKey('');
  }

  async function handleImportEnv(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedProjectId || !selectedEnvironmentId) return;

    const lines = importContent.split(/\r?\n/);
    const entries: { key: string; value: string }[] = [];

    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;

      // Support optional "export " prefix
      const withoutExport = line.startsWith('export ') ? line.slice(7) : line;
      const idx = withoutExport.indexOf('=');
      if (idx <= 0) continue;

      let key = withoutExport.slice(0, idx).trim();
      let value = withoutExport.slice(idx + 1).trim();

      // Strip matching surrounding quotes
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      if (!key) continue;
      entries.push({ key, value });
    }

    if (entries.length === 0) {
      showToast('no valid KEY=VALUE entries found', 'error');
      return;
    }

    setImporting(true);
    let imported = 0;
    let failed = 0;

    try {
      for (const { key, value } of entries) {
        try {
          await setEncryptedSecret(selectedProjectId, selectedEnvironmentId, key, value);
          imported++;
        } catch {
          failed++;
        }
      }
      await refreshSecrets();
      if (failed === 0) {
        showToast(`imported ${imported} secret${imported === 1 ? '' : 's'}`, 'success');
      } else {
        showToast(
          `imported ${imported}, failed ${failed}`,
          imported > 0 ? 'success' : 'error'
        );
      }
      setImportOpen(false);
      setImportContent('');
    } finally {
      setImporting(false);
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
      await disableTotpSession(s.token, s.email, disableTotpPassword, disableTotpCode);
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
          />
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
              <Button type="submit" className="w-full">
                Verify
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
              <Button type="submit" className="w-full">
                Continue
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
              <Button type="submit" className="w-full">
                Send reset link
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
              <Button type="submit" className="w-full">
                Reset password
              </Button>
            </form>
          </Card>
        </AuthLayout>
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
          onLogout={handleLogout}
        >
          {activeTab === 'secrets' && (
            <SecretsTab
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
              editingSecretKey={editingSecretKey}
              onSetSecret={handleSetSecret}
              onDeleteSecret={handleDeleteSecret}
              onStartEdit={handleStartEdit}
              onCancelEdit={handleCancelEdit}
              onOpenImport={() => setImportOpen(true)}
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
            />
          )}
          {activeTab === 'members' && (
            <MembersTab
              selectedProjectId={selectedProjectId}
              inviteEmail={inviteEmail}
              setInviteEmail={setInviteEmail}
              inviteRole={inviteRole}
              setInviteRole={setInviteRole}
              onInvite={handleInvite}
            />
          )}
          {activeTab === 'settings' && (
            <SettingsTab
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
        </Dashboard>
      )}

      {importOpen && (
        <ImportEnvModal
          content={importContent}
          onChange={setImportContent}
          onSubmit={handleImportEnv}
          onClose={() => {
            setImportOpen(false);
            setImportContent('');
          }}
          importing={importing}
        />
      )}

      {recoveryCode && <RecoveryCodeModal code={recoveryCode} onClose={() => setRecoveryCode('')} />}

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}

export default App;
