import { useState, useRef, useEffect } from 'react';
import { Shield, Eye, EyeOff, AlertCircle, ArrowLeft, Key, ShieldCheck, Loader2 } from 'lucide-react';
import { useLogin, useVerify2FA, useOIDCConfig, useOIDCAuthorize } from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import ThemeToggle from '../components/ThemeToggle';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [twoFAError, setTwoFAError] = useState('');

  const login = useLogin();
  const verify2FA = useVerify2FA();
  const { pending2FA, pending2FAToken, pending2FAUser, clearPending2FA } = useAuthStore();
  const { data: oidcConfig } = useOIDCConfig();
  const oidcAuthorize = useOIDCAuthorize();

  const totpInputRef = useRef<HTMLInputElement>(null);

  // Focus TOTP input when showing 2FA form
  useEffect(() => {
    if (pending2FA && totpInputRef.current) {
      totpInputRef.current.focus();
    }
  }, [pending2FA]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    login.mutate({ username, password });
  };

  const handleVerify2FA = (e: React.FormEvent) => {
    e.preventDefault();
    setTwoFAError('');
    if (!pending2FAToken) return;

    verify2FA.mutate(
      { pendingToken: pending2FAToken, code: totpCode },
      {
        onError: () => {
          setTwoFAError('Invalid authentication code');
          setTotpCode('');
        },
      }
    );
  };

  const handleBack = () => {
    clearPending2FA();
    setTotpCode('');
    setTwoFAError('');
  };

  const handleSSOLogin = async () => {
    try {
      const result = await oidcAuthorize.mutateAsync();
      // Store state and generate PKCE code verifier for callback
      const codeVerifier = generateCodeVerifier();
      sessionStorage.setItem('oidc_state', result.state);
      sessionStorage.setItem('oidc_code_verifier', codeVerifier);
      // Redirect to Authentik
      window.location.href = result.authorization_url;
    } catch (error) {
      console.error('Failed to initiate SSO login:', error);
    }
  };

  // Helper to generate PKCE code verifier (matches backend)
  function generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // Show 2FA verification form
  if (pending2FA) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 via-gray-50 to-white dark:from-zinc-900 dark:via-zinc-800 dark:to-zinc-900 px-4">
        <div className="absolute top-4 right-4">
          <ThemeToggle />
        </div>

        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl bg-primary-600 mb-4">
              <Key className="w-10 h-10 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Two-Factor Authentication</h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Enter the code from your authenticator app
            </p>
          </div>

          <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-xl p-8">
            <div className="flex items-center gap-2 mb-6">
              <button
                onClick={handleBack}
                className="p-1 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <ArrowLeft className="w-5 h-5" />
              </button>
              <span className="text-sm text-gray-600 dark:text-gray-400">
                Signing in as <span className="font-medium text-gray-900 dark:text-white">{pending2FAUser?.username}</span>
              </span>
            </div>

            {twoFAError && (
              <div className="mb-4 p-3 bg-danger-50 dark:bg-danger-900/30 border border-danger-200 dark:border-danger-800 rounded-lg flex items-center gap-2 text-danger-700 dark:text-danger-400 text-sm">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{twoFAError}</span>
              </div>
            )}

            <form onSubmit={handleVerify2FA} className="space-y-4">
              <div>
                <label
                  htmlFor="totp"
                  className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
                >
                  Authentication Code
                </label>
                <input
                  ref={totpInputRef}
                  id="totp"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9A-Za-z]*"
                  autoComplete="one-time-code"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\s/g, ''))}
                  className="input text-center text-2xl tracking-widest"
                  placeholder="000000"
                  required
                  maxLength={8}
                />
                <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                  Enter the 6-digit code or a backup code
                </p>
              </div>

              <button
                type="submit"
                disabled={verify2FA.isPending || totpCode.length < 6}
                className="btn-primary w-full py-2.5"
              >
                {verify2FA.isPending ? 'Verifying...' : 'Verify'}
              </button>
            </form>
          </div>

          <p className="mt-6 text-center text-sm text-gray-500">
            Lost access? Contact your administrator
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 via-gray-50 to-white dark:from-zinc-900 dark:via-zinc-800 dark:to-zinc-900 px-4">
      {/* Theme toggle in corner */}
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl bg-primary-600 mb-4">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">NetGuardian AI</h1>
          <p className="mt-2 text-gray-600 dark:text-gray-400">
            AI-Powered Home Network Security
          </p>
        </div>

        {/* Login form */}
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-xl p-8">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">
            Sign in to your account
          </h2>

          {login.isError && (
            <div className="mb-4 p-3 bg-danger-50 dark:bg-danger-900/30 border border-danger-200 dark:border-danger-800 rounded-lg flex items-center gap-2 text-danger-700 dark:text-danger-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>Invalid username or password</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="username"
                className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
              >
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="input"
                placeholder="Enter your username"
                required
                autoComplete="username"
              />
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input pr-10"
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  {showPassword ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={login.isPending}
              className="btn-primary w-full py-2.5"
            >
              {login.isPending ? 'Signing in...' : 'Sign in'}
            </button>
          </form>

          {/* SSO Login Button */}
          {oidcConfig?.enabled && (
            <>
              <div className="relative my-6">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-200 dark:border-zinc-700" />
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="bg-white dark:bg-zinc-800 px-2 text-gray-500 dark:text-gray-400">
                    Or continue with
                  </span>
                </div>
              </div>

              <button
                type="button"
                onClick={handleSSOLogin}
                disabled={oidcAuthorize.isPending}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 border border-gray-300 dark:border-zinc-600 rounded-lg text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-zinc-700 transition-colors disabled:opacity-50"
              >
                {oidcAuthorize.isPending ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <ShieldCheck className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                )}
                <span>Sign in with Authentik</span>
              </button>
            </>
          )}
        </div>

        <p className="mt-6 text-center text-sm text-gray-500">
          Contact your administrator if you need an account
        </p>
      </div>
    </div>
  );
}
