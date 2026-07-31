import { QRCodeSVG } from 'qrcode.react';
import { KeyRound, Lock, Shield } from './icons';
import { Badge, Button, Card, CardHeader, Input, Label } from './ui';

interface SettingsTabProps {
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
}

export function SettingsTab(props: SettingsTabProps) {
  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Settings</h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Manage your account security and recovery options.
        </p>
      </div>

      <Card>
        <CardHeader
          title="Two-factor authentication"
          description="Require a time-based code from an authenticator app when signing in."
          action={<Shield className="text-slate-400" size={20} />}
        />

        <div className="space-y-6 p-5">
          {props.totpEnabled ? (
            <div className="space-y-5">
              <div className="flex items-center gap-2">
                <Badge variant="success">Enabled</Badge>
              </div>

              <form onSubmit={props.onDisableTotp} className="space-y-4">
                <div>
                  <Label htmlFor="disable-password">Current password</Label>
                  <Input
                    id="disable-password"
                    type="password"
                    placeholder="••••••••"
                    value={props.disableTotpPassword}
                    onChange={(e) => props.setDisableTotpPassword(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="disable-totp-code">TOTP code</Label>
                  <Input
                    id="disable-totp-code"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="000000"
                    value={props.disableTotpCode}
                    onChange={(e) => props.setDisableTotpCode(e.target.value)}
                    required
                  />
                </div>
                <Button type="submit" variant="secondary">
                  Disable 2FA
                </Button>
              </form>
            </div>
          ) : (
            <div className="space-y-5">
              <div className="flex items-center gap-2">
                <Badge variant="default">Not enabled</Badge>
              </div>

              {!props.totpSecret ? (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900/50">
                  <div className="flex items-start gap-3">
                    <Lock className="mt-0.5 text-primary-600" size={18} />
                    <p className="text-sm text-slate-600 dark:text-slate-300">
                      Add an extra layer of security with an authenticator app such as{' '}
                      <strong>Google Authenticator</strong>, <strong>1Password</strong>, or{' '}
                      <strong>Authy</strong>.
                    </p>
                  </div>
                </div>
              ) : null}

              {!props.totpSecret ? (
                <Button onClick={props.onSetupTotp}>Setup 2FA</Button>
              ) : (
                <form onSubmit={props.onVerifyTotp} className="space-y-5">
                  <div className="flex flex-col items-start gap-5 sm:flex-row">
                    <div className="rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-700 dark:bg-slate-800">
                      <QRCodeSVG value={props.totpUri} size={168} />
                    </div>
                    <div className="flex-1 space-y-3">
                      <p className="text-sm text-slate-600 dark:text-slate-300">
                        Scan the QR code with your authenticator app, then enter the 6-digit code
                        to confirm.
                      </p>
                      <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-900/50">
                        <Label className="mb-1">Manual entry key</Label>
                        <code className="block break-all text-xs font-mono text-slate-700 dark:text-slate-300">
                          {props.totpSecret}
                        </code>
                      </div>
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="totp-verify-code">Verification code</Label>
                    <Input
                      id="totp-verify-code"
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="Enter code from app"
                      value={props.totpVerifyCode}
                      onChange={(e) => props.setTotpVerifyCode(e.target.value)}
                      required
                    />
                  </div>
                  <Button type="submit">Enable 2FA</Button>
                </form>
              )}
            </div>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Account recovery"
          description="Your recovery code was shown when you created your account."
          action={<KeyRound className="text-slate-400" size={20} />}
        />
        <div className="p-5">
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Without your recovery code, password resets are impossible. Store it in a secure
            password manager or offline location.
          </p>
        </div>
      </Card>
    </div>
  );
}
