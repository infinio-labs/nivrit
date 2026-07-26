import { Button, Card, Input, Label } from './ui';

export function AuthScreen({
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
    <Card className="w-full max-w-md p-6 shadow-lg sm:p-8">
      <div className="mb-8 text-center">
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
          {isRegister ? 'Create your account' : 'Sign in to your vault'}
        </h1>
        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
          {isRegister
            ? 'Start managing secrets with end-to-end encryption.'
            : 'Welcome back. Please enter your details.'}
        </p>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-2 rounded-lg bg-slate-100 p-1 dark:bg-slate-800">
        <button
          type="button"
          onClick={() => setIsRegister(false)}
          className={`rounded-md py-2 text-sm font-medium transition-all ${
            !isRegister
              ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-white'
              : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          Sign in
        </button>
        <button
          type="button"
          onClick={() => setIsRegister(true)}
          className={`rounded-md py-2 text-sm font-medium transition-all ${
            isRegister
              ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-white'
              : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
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
            autoComplete="email"
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
            autoComplete={isRegister ? 'new-password' : 'current-password'}
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
              autoComplete="name"
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
          <button
            type="button"
            onClick={onForgot}
            className="text-sm font-medium text-primary-600 hover:text-primary-700 hover:underline dark:text-primary-400"
          >
            Forgot password?
          </button>
        </div>
      )}

      <div className="my-6 flex items-center gap-3">
        <div className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />
        <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">
          or continue with
        </span>
        <div className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <Button type="button" variant="secondary" onClick={() => onOAuth('google')}>
          <GoogleIcon />
          Google
        </Button>
        <Button type="button" variant="secondary" onClick={() => onOAuth('github')}>
          <GitHubIcon />
          GitHub
        </Button>
      </div>
    </Card>
  );
}

function GoogleIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  );
}

function GitHubIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.419-1.305.762-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  );
}
